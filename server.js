// PAKPRO Audit System - Enhanced Multi-User Version
const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const XLSX = require('xlsx');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pakpro-audit-secret-key';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200 // Increased for field teams
});
app.use('/api/', limiter);

// Database setup with enhanced schema
const db = new Database('./pakpro_audits.db');

// Initialize database with enhanced tables
function initializeDatabase() {
  try {
    // Users table with enhanced fields
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'field_auditor',
        full_name TEXT,
        department TEXT,
        phone TEXT,
        is_active INTEGER DEFAULT 1,
        last_login DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Enhanced audits table
    db.exec(`
      CREATE TABLE IF NOT EXISTS audits (
        id TEXT PRIMARY KEY,
        created_by INTEGER NOT NULL,
        assigned_analyst INTEGER,
        status TEXT DEFAULT 'draft',
        priority TEXT DEFAULT 'normal',
        entity_name TEXT,
        contract_ref TEXT,
        location TEXT,
        audit_type TEXT,
        general_info TEXT,
        validation_data TEXT,
        conclusions_data TEXT,
        analyst_notes TEXT,
        completion_percentage INTEGER DEFAULT 0,
        due_date DATE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        submitted_at DATETIME,
        reviewed_at DATETIME,
        finalized_at DATETIME,
        FOREIGN KEY (created_by) REFERENCES users (id),
        FOREIGN KEY (assigned_analyst) REFERENCES users (id)
      )
    `);

    // Audit activity log table
    db.exec(`
      CREATE TABLE IF NOT EXISTS audit_activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        activity_type TEXT NOT NULL,
        description TEXT,
        old_status TEXT,
        new_status TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (audit_id) REFERENCES audits (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Comments table for collaboration
    db.exec(`
      CREATE TABLE IF NOT EXISTS audit_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        comment TEXT NOT NULL,
        is_internal INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (audit_id) REFERENCES audits (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Notifications table
    db.exec(`
      CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        audit_id TEXT,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (audit_id) REFERENCES audits (id)
      )
    `);

    console.log('Enhanced database tables initialized');

    // Create default users
    const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get();
    if (userCount.count === 0) {
      createDefaultUsers();
    }
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Create default users with different roles
async function createDefaultUsers() {
  const users = [
    {
      username: 'admin',
      email: 'admin@pakpro.com',
      password: 'pakpro123',
      role: 'data_analyst',
      full_name: 'System Administrator',
      department: 'Data Analysis'
    },
    {
      username: 'analyst1',
      email: 'analyst1@pakpro.com',
      password: 'analyst123',
      role: 'data_analyst',
      full_name: 'Data Analyst 1',
      department: 'Data Analysis'
    },
    {
      username: 'auditor1',
      email: 'auditor1@pakpro.com',
      password: 'auditor123',
      role: 'field_auditor',
      full_name: 'Field Auditor 1',
      department: 'Field Operations'
    }
  ];

  for (const user of users) {
    try {
      const hashedPassword = await bcrypt.hash(user.password, 10);
      const stmt = db.prepare(`
        INSERT INTO users (username, email, password_hash, role, full_name, department)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      stmt.run(user.username, user.email, hashedPassword, user.role, user.full_name, user.department);
      console.log(`Created ${user.role}: ${user.username} / ${user.password}`);
    } catch (error) {
      console.error(`Error creating user ${user.username}:`, error);
    }
  }
}

// Enhanced JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Update last login
    try {
      const stmt = db.prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
      stmt.run(user.userId);
    } catch (error) {
      console.error('Error updating last login:', error);
    }
    
    req.user = user;
    next();
  });
}

// Role-based access control
function requireRole(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Activity logging function
function logActivity(auditId, userId, activityType, description, oldStatus = null, newStatus = null) {
  try {
    const stmt = db.prepare(`
      INSERT INTO audit_activities (audit_id, user_id, activity_type, description, old_status, new_status)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(auditId, userId, activityType, description, oldStatus, newStatus);
  } catch (error) {
    console.error('Error logging activity:', error);
  }
}

// Notification function
function createNotification(userId, auditId, type, title, message) {
  try {
    const stmt = db.prepare(`
      INSERT INTO notifications (user_id, audit_id, type, title, message)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(userId, auditId, type, title, message);
  } catch (error) {
    console.error('Error creating notification:', error);
  }
}

// Routes

// Enhanced login with role information
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const stmt = db.prepare("SELECT * FROM users WHERE username = ? AND is_active = 1");
    const user = stmt.get(username);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials or account disabled' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        fullName: user.full_name,
        department: user.department
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create new user (analysts only)
app.post('/api/users/create', authenticateToken, requireRole(['data_analyst']), async (req, res) => {
  try {
    const { username, email, password, role, fullName, department, phone } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (!['field_auditor', 'data_analyst'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const stmt = db.prepare(`
        INSERT INTO users (username, email, password_hash, role, full_name, department, phone)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const result = stmt.run(username, email, hashedPassword, role, fullName, department, phone);

      res.status(201).json({ 
        message: 'User created successfully',
        userId: result.lastInsertRowid
      });
    } catch (dbError) {
      if (dbError.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Username or email already exists' });
      }
      throw dbError;
    }
  } catch (error) {
    console.error('User creation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
  try {
    const stats = {};

    if (req.user.role === 'data_analyst') {
      // Analyst dashboard
      const totalAudits = db.prepare("SELECT COUNT(*) as count FROM audits").get().count;
      const pendingReview = db.prepare("SELECT COUNT(*) as count FROM audits WHERE status = 'pending_review'").get().count;
      const inProgress = db.prepare("SELECT COUNT(*) as count FROM audits WHERE status IN ('draft', 'in_progress')").get().count;
      const completed = db.prepare("SELECT COUNT(*) as count FROM audits WHERE status = 'finalized'").get().count;
      
      stats.totalAudits = totalAudits;
      stats.pendingReview = pendingReview;
      stats.inProgress = inProgress;
      stats.completed = completed;
      
      // Recent activity
      const recentActivity = db.prepare(`
        SELECT a.*, u.full_name as user_name
        FROM audit_activities a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 10
      `).all();
      stats.recentActivity = recentActivity;
      
    } else {
      // Field auditor dashboard
      const myAudits = db.prepare("SELECT COUNT(*) as count FROM audits WHERE created_by = ?").get(req.user.userId).count;
      const myDrafts = db.prepare("SELECT COUNT(*) as count FROM audits WHERE created_by = ? AND status = 'draft'").get(req.user.userId).count;
      const mySubmitted = db.prepare("SELECT COUNT(*) as count FROM audits WHERE created_by = ? AND status IN ('pending_review', 'in_review')").get(req.user.userId).count;
      const myCompleted = db.prepare("SELECT COUNT(*) as count FROM audits WHERE created_by = ? AND status = 'finalized'").get(req.user.userId).count;
      
      stats.myAudits = myAudits;
      stats.myDrafts = myDrafts;
      stats.mySubmitted = mySubmitted;
      stats.myCompleted = myCompleted;
    }

    res.json(stats);
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

// Enhanced audit creation with workflow
app.post('/api/audits', authenticateToken, (req, res) => {
  const { id, status, generalInfo, validation, conclusions, analystNotes, assignedAnalyst } = req.body;
  const auditId = id || `AUDIT-${Date.now()}`;
  const userId = req.user.userId;

  const entityName = generalInfo?.entityName || '';
  const contractRef = generalInfo?.contractRef || '';
  const location = generalInfo?.entityAddress || '';

  try {
    // Check if audit exists
    const existingStmt = db.prepare("SELECT * FROM audits WHERE id = ?");
    const existingAudit = existingStmt.get(auditId);

    const generalInfoJson = JSON.stringify(generalInfo || {});
    const validationJson = JSON.stringify(validation || {});
    const conclusionsJson = JSON.stringify(conclusions || {});

    // Calculate completion percentage
    const fields = [
      generalInfo?.entityName,
      generalInfo?.contractRef,
      validation?.spotChecks,
      conclusions?.assessmentStatus
    ];
    const completedFields = fields.filter(field => field && field.trim()).length;
    const completionPercentage = Math.round((completedFields / fields.length) * 100);

    if (existingAudit) {
      // Update existing audit
      const updateStmt = db.prepare(`
        UPDATE audits SET 
        status = ?, entity_name = ?, contract_ref = ?, location = ?,
        general_info = ?, validation_data = ?, conclusions_data = ?,
        analyst_notes = ?, assigned_analyst = ?, completion_percentage = ?,
        updated_at = CURRENT_TIMESTAMP,
        submitted_at = CASE WHEN status = 'pending_review' AND ? != 'pending_review' THEN CURRENT_TIMESTAMP ELSE submitted_at END,
        reviewed_at = CASE WHEN status = 'in_review' AND ? != 'in_review' THEN CURRENT_TIMESTAMP ELSE reviewed_at END,
        finalized_at = CASE WHEN status = 'finalized' AND ? != 'finalized' THEN CURRENT_TIMESTAMP ELSE finalized_at END
        WHERE id = ?
      `);
      
      updateStmt.run(status, entityName, contractRef, location, generalInfoJson, validationJson, 
                    conclusionsJson, analystNotes, assignedAnalyst, completionPercentage,
                    existingAudit.status, existingAudit.status, existingAudit.status, auditId);

      // Log status change if it changed
      if (existingAudit.status !== status) {
        logActivity(auditId, userId, 'status_change', 
                   `Status changed from ${existingAudit.status} to ${status}`, 
                   existingAudit.status, status);

        // Create notifications for status changes
        if (status === 'pending_review' && req.user.role === 'field_auditor') {
          // Notify analysts when audit is submitted for review
          const analysts = db.prepare("SELECT id FROM users WHERE role = 'data_analyst' AND is_active = 1").all();
          analysts.forEach(analyst => {
            createNotification(analyst.id, auditId, 'audit_submitted', 
                             'New Audit for Review', 
                             `Audit ${auditId} has been submitted for review by ${req.user.username}`);
          });
        }
      }

      res.json({
        message: 'Audit updated successfully',
        audit: { id: auditId, action: 'updated' }
      });
    } else {
      // Create new audit
      const insertStmt = db.prepare(`
        INSERT INTO audits (id, created_by, status, entity_name, contract_ref, location,
                           general_info, validation_data, conclusions_data, completion_percentage)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      
      insertStmt.run(auditId, userId, status, entityName, contractRef, location,
                    generalInfoJson, validationJson, conclusionsJson, completionPercentage);

      logActivity(auditId, userId, 'created', 'Audit created');

      res.status(201).json({
        message: 'Audit created successfully',
        audit: { id: auditId, action: 'created' }
      });
    }
  } catch (error) {
    console.error('Error saving audit:', error);
    res.status(500).json({ error: 'Failed to save audit' });
  }
});

// Enhanced audit listing with role-based filtering
app.get('/api/audits', authenticateToken, (req, res) => {
  const { status, search, assigned_to_me, created_by_me } = req.query;

  try {
    let query = `
      SELECT a.*, 
             creator.username as created_by_username,
             creator.full_name as created_by_name,
             analyst.username as assigned_analyst_username,
             analyst.full_name as assigned_analyst_name
      FROM audits a 
      JOIN users creator ON a.created_by = creator.id
      LEFT JOIN users analyst ON a.assigned_analyst = analyst.id
    `;
    const params = [];
    const conditions = [];

    // Role-based filtering
    if (req.user.role === 'field_auditor' && !created_by_me) {
      conditions.push('a.created_by = ?');
      params.push(req.user.userId);
    }

    if (status) {
      conditions.push('a.status = ?');
      params.push(status);
    }

    if (search) {
      conditions.push('(a.entity_name LIKE ? OR a.contract_ref LIKE ? OR a.id LIKE ?)');
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    if (assigned_to_me === 'true') {
      conditions.push('a.assigned_analyst = ?');
      params.push(req.user.userId);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY a.updated_at DESC';

    const stmt = db.prepare(query);
    const rows = stmt.all(...params);

    const audits = rows.map(row => ({
      id: row.id,
      status: row.status,
      priority: row.priority,
      entityName: row.entity_name,
      contractRef: row.contract_ref,
      location: row.location,
      completionPercentage: row.completion_percentage,
      createdBy: row.created_by_username,
      createdByName: row.created_by_name,
      assignedAnalyst: row.assigned_analyst_username,
      assignedAnalystName: row.assigned_analyst_name,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      submittedAt: row.submitted_at,
      dueDate: row.due_date,
      generalInfo: row.general_info ? JSON.parse(row.general_info) : {},
      validation: row.validation_data ? JSON.parse(row.validation_data) : {},
      conclusions: row.conclusions_data ? JSON.parse(row.conclusions_data) : {},
      analystNotes: row.analyst_notes
    }));

    res.json({ audits });
  } catch (error) {
    console.error('Error fetching audits:', error);
    res.status(500).json({ error: 'Failed to fetch audits' });
  }
});

// Get notifications
app.get('/api/notifications', authenticateToken, (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT n.*, a.entity_name
      FROM notifications n
      LEFT JOIN audits a ON n.audit_id = a.id
      WHERE n.user_id = ?
      ORDER BY n.created_at DESC
      LIMIT 50
    `);
    const notifications = stmt.all(req.user.userId);

    res.json({ notifications });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Mark notification as read
app.patch('/api/notifications/:id/read', authenticateToken, (req, res) => {
  try {
    const stmt = db.prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?");
    const result = stmt.run(req.params.id, req.user.userId);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ error: 'Failed to update notification' });
  }
});

// Enhanced Excel export with analyst notes and workflow data
app.get('/api/audits/export', authenticateToken, requireRole(['data_analyst']), (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT a.*, 
             creator.full_name as created_by_name,
             analyst.full_name as assigned_analyst_name
      FROM audits a 
      JOIN users creator ON a.created_by = creator.id
      LEFT JOIN users analyst ON a.assigned_analyst = analyst.id
      ORDER BY a.updated_at DESC
    `);
    const rows = stmt.all();

    if (rows.length === 0) {
      return res.status(404).json({ error: 'No audits found to export' });
    }

    // Enhanced Excel data with workflow information
    const excelData = rows.map(row => {
      const generalInfo = row.general_info ? JSON.parse(row.general_info) : {};
      const validation = row.validation_data ? JSON.parse(row.validation_data) : {};
      const conclusions = row.conclusions_data ? JSON.parse(row.conclusions_data) : {};

      return {
        'Audit ID': row.id,
        'Status': row.status,
        'Priority': row.priority,
        'Completion %': row.completion_percentage,
        'Entity Name': row.entity_name,
        'Contract Reference': row.contract_ref,
        'Location': row.location,
        'Created By': row.created_by_name,
        'Assigned Analyst': row.assigned_analyst_name || 'Unassigned',
        'Created Date': new Date(row.created_at).toLocaleDateString(),
        'Updated Date': new Date(row.updated_at).toLocaleDateString(),
        'Submitted Date': row.submitted_at ? new Date(row.submitted_at).toLocaleDateString() : '',
        'Due Date': row.due_date || '',
        
        // General Information
        'Entity Address': generalInfo.entityAddress || '',
        'Verification Period': generalInfo.verificationPeriod || '',
        'Project Title': generalInfo.projectTitle || '',
        'Auditee Team Leader': generalInfo.auditeeTeamLeader || '',
        'Start Date': generalInfo.startDate || '',
        'On-site Date': generalInfo.onSiteDate || '',
        
        // Validation
        'Spot Checks Conducted': validation.spotChecks || '',
        'Rejected Material': validation.rejectedMaterial || '',
        'Rejection Details': validation.rejectionDetails || '',
        'Contract Amendments': validation.contractAmendments || '',
        'Amendment Details': validation.amendmentDetails || '',
        'Additional Comments': validation.additionalComments || '',
        
        // Conclusions
        'Assessment Status': conclusions.assessmentStatus || '',
        'Audit Team Leader': conclusions.auditTeamLeader || '',
        'Audit Date': conclusions.auditDate || '',
        'Conclusion Comments': conclusions.conclusionComments || '',
        
        // Analyst Notes
        'Analyst Notes': row.analyst_notes || ''
      };
    });

    // Create workbook with multiple sheets
    const workbook = XLSX.utils.book_new();
    
    // Main data sheet
    const worksheet = XLSX.utils.json_to_sheet(excelData);
    const colWidths = Object.keys(excelData[0] || {}).map(key => ({ wch: Math.max(key.length, 15) }));
    worksheet['!cols'] = colWidths;
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Audit Data');

    // Summary statistics sheet
    const summaryData = [
      ['PAKPRO Audit Summary Report'],
      ['Generated:', new Date().toLocaleString()],
      [''],
      ['Status Distribution'],
      ['Draft', rows.filter(r => r.status === 'draft').length],
      ['Pending Review', rows.filter(r => r.status === 'pending_review').length],
      ['In Review', rows.filter(r => r.status === 'in_review').length],
      ['Finalized', rows.filter(r => r.status === 'finalized').length],
      [''],
      ['Completion Statistics'],
      ['Average Completion %', Math.round(rows.reduce((sum, r) => sum + r.completion_percentage, 0) / rows.length)],
      ['Total Audits', rows.length]
    ];
    
    const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
    summarySheet['!cols'] = [{ wch: 20 }, { wch: 15 }];
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');

    const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

    res.setHeader('Content-Disposition', `attachment; filename=PAKPRO_Full_Export_${new Date().toISOString().split('T')[0]}.xlsx`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

    res.send(buffer);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Failed to export audits' });
  }
});

// All other existing routes remain the same...
// (Include all previous routes: health check, user info, single audit, delete, etc.)

// Initialize and start server
try {
  initializeDatabase();
  
  app.listen(PORT, () => {
    console.log(`PAKPRO Enhanced Audit Server running on port ${PORT}`);
    console.log(`Access the application at: http://localhost:${PORT}`);
    console.log('Default users created:');
    console.log('  Data Analyst: admin / pakpro123');
    console.log('  Data Analyst: analyst1 / analyst123');
    console.log('  Field Auditor: auditor1 / auditor123');
  });
} catch (error) {
  console.error('Failed to start server:', error);
  process.exit(1);
}

module.exports = app;