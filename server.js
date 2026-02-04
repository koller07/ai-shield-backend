// ============================================
// AI-SHIELD BACKEND SERVER
// Receives detections, stores in database,
// generates reports automatically
// ============================================
const fs = require('fs');

// Initialize database tables
async function initializeDatabase() {
  try {
    const sql = fs.readFileSync('./init.sql', 'utf8');
    await pool.query(sql);
    console.log('Database tables initialized');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Call on startup
initializeDatabase();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const schedule = require('node-schedule');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected:', res.rows[0]);
  }
});

// ============================================
// ENDPOINTS
// ============================================

// 1. Receive detection from extension
app.post('/api/detection', async (req, res) => {
  const { userId, companyId, detectionType, aiPlatform, timestamp } = req.body;
  
  try {
    await pool.query(
      'INSERT INTO detections (user_id, company_id, detection_type, ai_platform, timestamp) VALUES ($1, $2, $3, $4, $5)',
      [userId, companyId, detectionType, aiPlatform, timestamp]
    );
    
    res.json({ success: true, message: 'Detection recorded' });
  } catch (error) {
    console.error('Error saving detection:', error);
    res.status(500).json({ error: 'Failed to save detection' });
  }
});

// 2. Get report for company
app.get('/api/report/:companyId/:month/:year', async (req, res) => {
  const { companyId, month, year } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT user_id, detection_type, COUNT(*) as count 
       FROM detections 
       WHERE company_id = $1 
       AND EXTRACT(MONTH FROM timestamp) = $2 
       AND EXTRACT(YEAR FROM timestamp) = $3 
       GROUP BY user_id, detection_type
       ORDER BY count DESC`,
      [companyId, month, year]
    );
    
    const totalDetections = result.rows.reduce((sum, row) => sum + parseInt(row.count), 0);
    
    res.json({
      companyId,
      month,
      year,
      totalDetections,
      finePrevented: totalDetections * 50000,
      byUser: result.rows
    });
  } catch (error) {
    console.error('Error generating report:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// 3. Get all detections for company
app.get('/api/detections/:companyId', async (req, res) => {
  const { companyId } = req.params;
  
  try {
    const result = await pool.query(
      'SELECT * FROM detections WHERE company_id = $1 ORDER BY timestamp DESC LIMIT 100',
      [companyId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching detections:', error);
    res.status(500).json({ error: 'Failed to fetch detections' });
  }
});

// 4. Create company
app.post('/api/companies', async (req, res) => {
  const { name, adminEmail, plan } = req.body;
  const companyId = require('crypto').randomUUID();
  
  try {
    await pool.query(
      'INSERT INTO companies (id, name, admin_email, plan) VALUES ($1, $2, $3, $4)',
      [companyId, name, adminEmail, plan]
    );
    
    res.json({ companyId, message: 'Company created' });
  } catch (error) {
    console.error('Error creating company:', error);
    res.status(500).json({ error: 'Failed to create company' });
  }
});

// ============================================
// SCHEDULED TASKS
// ============================================

// Send monthly reports on 1st of month at 8:00 AM
schedule.scheduleJob('0 8 1 * *', async () => {
  console.log('Sending monthly reports...');
  
  try {
    const companies = await pool.query('SELECT * FROM companies WHERE active = true');
    
    for (const company of companies.rows) {
      const now = new Date();
      const lastMonth = now.getMonth() === 0 ? 12 : now.getMonth();
      const lastYear = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();
      
      // Generate report
      const reportData = await pool.query(
        `SELECT user_id, detection_type, COUNT(*) as count 
         FROM detections 
         WHERE company_id = $1 
         AND EXTRACT(MONTH FROM timestamp) = $2 
         AND EXTRACT(YEAR FROM timestamp) = $3 
         GROUP BY user_id, detection_type`,
        [company.id, lastMonth, lastYear]
      );
      
      const totalDetections = reportData.rows.reduce((sum, row) => sum + parseInt(row.count), 0);
      
      // Send email
      await sendReportEmail(
        company.admin_email,
        company.name,
        lastMonth,
        lastYear,
        totalDetections,
        reportData.rows
      );
    }
  } catch (error) {
    console.error('Error sending reports:', error);
  }
});

// ============================================
// EMAIL FUNCTION
// ============================================

async function sendReportEmail(email, companyName, month, year, totalDetections, data) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  
  const monthName = new Date(year, month - 1).toLocaleString('en-US', { month: 'long' });
  
  let detailsHtml = data.map(row => 
    `<tr><td>${row.user_id}</td><td>${row.detection_type}</td><td>${row.count}</td></tr>`
  ).join('');
  
  const html = `
    <h1>AI-Shield Monthly Report</h1>
    <p>Hi ${companyName},</p>
    <p>Here's your report for ${monthName} ${year}:</p>
    
    <h2>Summary</h2>
    <p><strong>Total Detections:</strong> ${totalDetections}</p>
    <p><strong>Fine Prevented:</strong> €${(totalDetections * 50000).toLocaleString()}</p>
    
    <h2>Details by Employee</h2>
    <table border="1" cellpadding="10">
      <tr><th>Employee</th><th>Type</th><th>Count</th></tr>
      ${detailsHtml}
    </table>
    
    <p>Keep your team safe!</p>
    <p>AI-Shield Team</p>
  `;
  
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: `AI-Shield Report - ${monthName} ${year}`,
      html: html
    });
    
    console.log(`Report sent to ${email}`);
  } catch (error) {
    console.error('Error sending email:', error);
  }
}

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AI-Shield Backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
