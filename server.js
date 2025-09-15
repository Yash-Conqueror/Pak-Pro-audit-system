// PAKPRO Audit System - Railway Compatible (No Native Dependencies)
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const XLSX = require('xlsx');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pakpro-audit-secret-key';

// Data directory
const DATA_DIR = './data';
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const AUDITS_FILE = path.join(DATA_DIR, 'audits.json');
const ACTIVITIES_FILE = path.join(DATA_DIR, 'activities.json');
const NOTIFICATIONS_FILE = path.join(DATA_DIR, 'notifications.json');

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});
app.use('/api/', limiter);

// Data management functions
async function ensureDataDirectory() {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
  }
}

async function readJsonFile(filePath, defaultData = []) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch {
    return defaultData;
  }
}

async function writeJsonFile(filePath, data) {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2));
}

// Initialize database
async function initializeDatabase() {
  try {
    await ensureDataDirectory();
    
    // Initialize users
    const users = await readJsonFile(USERS_FILE, []);
    if (users.length === 0) {
      await createDefaultUsers();
    }
    
    // Initialize other files
    await readJsonFile(AUDITS_FILE, []);
    await readJsonFile(ACTIVITIES_FILE, []);
    await readJsonFile(NOTIFICATIONS_FILE, []);
    
    console.log('Database initialized with JSON files');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Create default users
async function createDefaultUsers() {
  const defaultUsers = [
    {
      id: 1,
      username: 'admin',
      email: 'admin@pakpro.com',
      password: 'pakpro123',
      role: 'data_analyst',
      fullName: 'System Administrator',
      department: 'Data Analysis',
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 2,
      username: 'analyst1',
      email: 'analyst1@pakpro.com',
      password: 'analyst123',
      role: 'data_analyst',
      fullName: 'Data Analyst 1',
      department: 'Data Analysis',
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 3,
      username: 'auditor1',
      email: 'auditor1@pakpro.com',
      password: 'auditor123',
      role: 'field_auditor',
      fullName: 'Field Auditor 1',
      department: 'Field Operations',
      isActive: true,
      createdAt: new Date().toISOString()
    }
  ];

  for (const user of defaultUsers) {
    user.passwordHash = await bcrypt.hash(user.password, 10);
    delete user.password;
  }

  await writeJsonFile(USERS_FILE, defaultUsers);
  console.log('Default users created:');
  console.log('  Data Analyst: admin / pakpro123');
  console.log('  Data Analyst: analyst1 / analyst123');
  console.log('  Field Auditor: auditor1 / auditor123');
}

// JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Update last login
    try {
      const users = await readJsonFile(USERS_FILE, []);
      const userIndex = users.findIndex(u => u.id === user.userId);
      if (userIndex >= 0) {
        users[userIndex].lastLogin = new Date().toISOString();
        await writeJsonFile(USERS_FILE, users);
      }
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

// Activity logging
async function logActivity(auditId, userId, activityType, description, oldStatus = null, newStatus = null) {
  try {
    const activities = await readJsonFile(ACTIVITIES_FILE, []);
    const newActivity = {
      id: Date.now(),
      auditId,
      userId,
      activityType,
      description,
      oldStatus,
      newStatus,
      createdAt: new Date().toISOString()
    };
    activities.push(newActivity);
    await writeJsonFile(ACTIVITIES_FILE, activities);
  } catch (error) {
    console.error('Error logging activity:', error);
  }
}

// Notification function
async function createNotification(userId, auditId, type, title, message) {
  try {
    const notifications = await readJsonFile(NOTIFICATIONS_FILE, []);
    const newNotification = {
      id: Date.now(),
      userId,
      auditId,
      type,
      title,
      message,
      isRead: false,
      createdAt: new Date().toISOString()
    };
    notifications.push(newNotification);
    await writeJsonFile(NOTIFICATIONS_FILE, notifications);
  } catch (error) {
    console.error('Error creating notification:', error);
  }
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'PAKPRO Audit API is running',
    timestamp: new Date().toISOString()
  });
});

// User login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const users = await readJsonFile(USERS_FILE, []);
    const user = users.find(u => u.username === username && u.isActive);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials or account disabled' });
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
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
        fullName: user.fullName,
        department: user.department
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create new user
app.post('/api/users/create', authenticateToken, requireRole(['data_analyst']), async (req, res) => {
  try {
    const { username, email, password, role, fullName, department, phone } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (!['field_auditor', 'data_analyst'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified' });
    }

    const users = await readJsonFile(USERS_FILE, []);
    
    // Check for existing username or email
    if (users.find(u => u.username === username || u.email === email)) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: Math.max(...users.map(u => u.id), 0) + 1,
      username,
      email,
      passwordHash: hashedPassword,
      role,
      fullName,
      department,
      phone,
      isActive: true,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await writeJsonFile(USERS_FILE, users);

    res.status(201).json({ 
      message: 'User created successfully',
      userId: newUser.id
    });
  } catch (error) {
    console.error('User creation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const audits = await readJsonFile(AUDITS_FILE, []);
    const stats = {};

    if (req.user.role === 'data_analyst') {
      // Analyst dashboard
      stats.totalAudits = audits.length;
      stats.pendingReview = audits.filter(a => a.status === 'pending_review').length;
      stats.inProgress = audits.filter(a => ['draft', 'in_progress'].includes(a.status)).length;
      stats.completed = audits.filter(a => a.status === 'finalized').length;
      
      // Recent activity
      const activities = await readJsonFile(ACTIVITIES_FILE, []);
      const users = await readJsonFile(USERS_FILE, []);
      
      const recentActivity = activities
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice(0, 10)
        .map(activity => {
          const user = users.find(u => u.id === activity.userId);
          return {
            ...activity,
            userName: user ? user.fullName : 'Unknown User'
          };
        });
      
      stats.recentActivity = recentActivity;
      
    } else {
      // Field auditor dashboard
      const myAudits = audits.filter(a => a.createdBy === req.user.userId);
      stats.myAudits = myAudits.length;
      stats.myDrafts = myAudits.filter(a => a.status === 'draft').length;
      stats.mySubmitted = myAudits.filter(a => ['pending_review', 'in_review'].includes(a.status)).length;
      stats.myCompleted = myAudits.filter(a => a.status === 'finalized').length;
    }

    res.json(stats);
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

// Create or update audit
app.post('/api/audits', authenticateToken, async (req, res) => {
  try {
    const { id, status, generalInfo, validation, conclusions, analystNotes, assignedAnalyst } = req.body;
    const auditId = id || `AUDIT-${Date.now()}`;
    const userId = req.user.userId;

    const audits = await readJsonFile(AUDITS_FILE, []);
    const existingAuditIndex = audits.findIndex(a => a.id === auditId);

    const entityName = generalInfo?.entityName || '';
    const contractRef = generalInfo?.contractRef || '';
    const location = generalInfo?.entityAddress || '';

    // Calculate completion percentage
    const fields = [
      generalInfo?.entityName,
      generalInfo?.contractRef,
      validation?.spotChecks,
      conclusions?.assessmentStatus
    ];
    const completedFields = fields.filter(field => field && field.trim()).length;
    const completionPercentage = Math.round((completedFields / fields.length) * 100);

    const auditData = {
      id: auditId,
      status: status || 'draft',
      entityName,
      contractRef,
      location,
      generalInfo: generalInfo || {},
      validation: validation || {},
      conclusions: conclusions || {},
      analystNotes,
      assignedAnalyst,
      completionPercentage,
      updatedAt: new Date().toISOString()
    };

    if (existingAuditIndex >= 0) {
      // Update existing audit
      const existingAudit = audits[existingAuditIndex];
      auditData.createdBy = existingAudit.createdBy;
      auditData.createdAt = existingAudit.createdAt;
      
      // Update timestamps based on status changes
      if (status === 'pending_review' && existingAudit.status !== 'pending_review') {
        auditData.submittedAt = new Date().toISOString();
      }
      if (status === 'in_review' && existingAudit.status !== 'in_review') {
        auditData.reviewedAt = new Date().toISOString();
      }
      if (status === 'finalized' && existingAudit.status !== 'finalized') {
        auditData.finalizedAt = new Date().toISOString();
      }

      audits[existingAuditIndex] = auditData;

      // Log status change
      if (existingAudit.status !== status) {
        await logActivity(auditId, userId, 'status_change', 
                         `Status changed from ${existingAudit.status} to ${status}`, 
                         existingAudit.status, status);

        // Create notifications for status changes
        if (status === 'pending_review' && req.user.role === 'field_auditor') {
          const users = await readJsonFile(USERS_FILE, []);
          const analysts = users.filter(u => u.role === 'data_analyst' && u.isActive);
          
          for (const analyst of analysts) {
            await createNotification(analyst.id, auditId, 'audit_submitted', 
                                   'New Audit for Review', 
                                   `Audit ${auditId} has been submitted for review by ${req.user.username}`);
          }
        }
      }

      res.json({
        message: 'Audit updated successfully',
        audit: { id: auditId, action: 'updated' }
      });
    } else {
      // Create new audit
      auditData.createdBy = userId;
      auditData.createdAt = new Date().toISOString();
      audits.push(auditData);

      await logActivity(auditId, userId, 'created', 'Audit created');

      res.status(201).json({
        message: 'Audit created successfully',
        audit: { id: auditId, action: 'created' }
      });
    }

    await writeJsonFile(AUDITS_FILE, audits);
  } catch (error) {
    console.error('Error saving audit:', error);
    res.status(500).json({ error: 'Failed to save audit' });
  }
});

// Get audits with role-based filtering
app.get('/api/audits', authenticateToken, async (req, res) => {
  try {
    const { status, search, assigned_to_me, created_by_me } = req.query;
    
    let audits = await readJsonFile(AUDITS_FILE, []);
    const users = await readJsonFile(USERS_FILE, []);

    // Role-based filtering
    if (req.user.role === 'field_auditor' && !created_by_me) {
      audits = audits.filter(a => a.createdBy === req.user.userId);
    }

    // Apply filters
    if (status) {
      audits = audits.filter(a => a.status === status);
    }

    if (search) {
      const searchLower = search.toLowerCase();
      audits = audits.filter(a => 
        (a.entityName && a.entityName.toLowerCase().includes(searchLower)) ||
        (a.contractRef && a.contractRef.toLowerCase().includes(searchLower)) ||
        (a.id && a.id.toLowerCase().includes(searchLower))
      );
    }

    if (assigned_to_me === 'true') {
      audits = audits.filter(a => a.assignedAnalyst === req.user.userId);
    }

    // Add user information
    const enrichedAudits = audits.map(audit => {
      const creator = users.find(u => u.id === audit.createdBy);
      const analyst = users.find(u => u.id === audit.assignedAnalyst);
      
      return {
        ...audit,
        createdBy: creator ? creator.username : 'Unknown',
        createdByName: creator ? creator.fullName : 'Unknown',
        assignedAnalyst: analyst ? analyst.username : null,
        assignedAnalystName: analyst ? analyst.fullName : null
      };
    });

    // Sort by updated date (newest first)
    enrichedAudits.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

    res.json({ audits: enrichedAudits });
  } catch (error) {
    console.error('Error fetching audits:', error);
    res.status(500).json({ error: 'Failed to fetch audits' });
  }
});

// Get single audit
app.get('/api/audits/:id', authenticateToken, async (req, res) => {
  try {
    const auditId = req.params.id;
    const audits = await readJsonFile(AUDITS_FILE, []);
    const users = await readJsonFile(USERS_FILE, []);
    
    const audit = audits.find(a => a.id === auditId);
    if (!audit) {
      return res.status(404).json({ error: 'Audit not found' });
    }

    const creator = users.find(u => u.id === audit.createdBy);
    const analyst = users.find(u => u.id === audit.assignedAnalyst);

    const enrichedAudit = {
      ...audit,
      createdBy: creator ? creator.username : 'Unknown',
      createdByName: creator ? creator.fullName : 'Unknown',
      assignedAnalyst: analyst ? analyst.username : null,
      assignedAnalystName: analyst ? analyst.fullName : null
    };

    res.json({ audit: enrichedAudit });
  } catch (error) {
    console.error('Error fetching audit:', error);
    res.status(500).json({ error: 'Failed to fetch audit' });
  }
});

// Delete audit
app.delete('/api/audits/:id', authenticateToken, async (req, res) => {
  try {
    const auditId = req.params.id;
    const audits = await readJsonFile(AUDITS_FILE, []);
    
    const auditIndex = audits.findIndex(a => a.id === auditId);
    if (auditIndex === -1) {
      return res.status(404).json({ error: 'Audit not found' });
    }

    const audit = audits[auditIndex];
    
    // Check permissions
    if (audit.createdBy !== req.user.userId && req.user.role !== 'data_analyst') {
      return res.status(403).json({ error: 'Access denied' });
    }

    audits.splice(auditIndex, 1);
    await writeJsonFile(AUDITS_FILE, audits);

    res.json({ message: 'Audit deleted successfully' });
  } catch (error) {
    console.error('Error deleting audit:', error);
    res.status(500).json({ error: 'Failed to delete audit' });
  }
});

// Export audits to Excel
app.get('/api/audits/export', authenticateToken, requireRole(['data_analyst']), async (req, res) => {
  try {
    const audits = await readJsonFile(AUDITS_FILE, []);
    const users = await readJsonFile(USERS_FILE, []);

    if (audits.length === 0) {
      return res.status(404).json({ error: 'No audits found to export' });
    }

    // Prepare Excel data
    const excelData = audits.map(audit => {
      const creator = users.find(u => u.id === audit.createdBy);
      const analyst = users.find(u => u.id === audit.assignedAnalyst);

      return {
        'Audit ID': audit.id,
        'Status': audit.status,
        'Completion %': audit.completionPercentage || 0,
        'Entity Name': audit.entityName,
        'Contract Reference': audit.contractRef,
        'Location': audit.location,
        'Created By': creator ? creator.fullName : 'Unknown',
        'Assigned Analyst': analyst ? analyst.fullName : 'Unassigned',
        'Created Date': new Date(audit.createdAt).toLocaleDateString(),
        'Updated Date': new Date(audit.updatedAt).toLocaleDateString(),
        'Submitted Date': audit.submittedAt ? new Date(audit.submittedAt).toLocaleDateString() : '',
        
        // General Information
        'Entity Address': audit.generalInfo?.entityAddress || '',
        'Verification Period': audit.generalInfo?.verificationPeriod || '',
        'Project Title': audit.generalInfo?.projectTitle || '',
        'Auditee Team Leader': audit.generalInfo?.auditeeTeamLeader || '',
        'Start Date': audit.generalInfo?.startDate || '',
        'On-site Date': audit.generalInfo?.onSiteDate || '',
        
        // Validation
        'Spot Checks Conducted': audit.validation?.spotChecks || '',
        'Rejected Material': audit.validation?.rejectedMaterial || '',
        'Rejection Details': audit.validation?.rejectionDetails || '',
        'Contract Amendments': audit.validation?.contractAmendments || '',
        'Amendment Details': audit.validation?.amendmentDetails || '',
        'Additional Comments': audit.validation?.additionalComments || '',
        
        // Conclusions
        'Assessment Status': audit.conclusions?.assessmentStatus || '',
        'Audit Team Leader': audit.conclusions?.auditTeamLeader || '',
        'Audit Date': audit.conclusions?.auditDate || '',
        'Conclusion Comments': audit.conclusions?.conclusionComments || '',
        
        // Analyst Notes
        'Analyst Notes': audit.analystNotes || ''
      };
    });

    // Create workbook
    const workbook = XLSX.utils.book_new();
    const worksheet = XLSX.utils.json_to_sheet(excelData);
    
    // Auto-size columns
    const colWidths = Object.keys(excelData[0] || {}).map(key => ({ wch: Math.max(key.length, 15) }));
    worksheet['!cols'] = colWidths;
    
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Audit Data');

    // Summary sheet
    const summaryData = [
      ['PAKPRO Audit Summary Report'],
      ['Generated:', new Date().toLocaleString()],
      [''],
      ['Status Distribution'],
      ['Draft', audits.filter(a => a.status === 'draft').length],
      ['Pending Review', audits.filter(a => a.status === 'pending_review').length],
      ['In Review', audits.filter(a => a.status === 'in_review').length],
      ['Finalized', audits.filter(a => a.status === 'finalized').length],
      [''],
      ['Total Audits', audits.length]
    ];
    
    const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
    summarySheet['!cols'] = [{ wch: 20 }, { wch: 15 }];
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');

    const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

    res.setHeader('Content-Disposition', `attachment; filename=PAKPRO_Export_${new Date().toISOString().split('T')[0]}.xlsx`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

    res.send(buffer);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Failed to export audits' });
  }
});

// Export single audit
app.get('/api/audits/:id/export', authenticateToken, async (req, res) => {
  try {
    const auditId = req.params.id;
    const audits = await readJsonFile(AUDITS_FILE, []);
    const users = await readJsonFile(USERS_FILE, []);
    
    const audit = audits.find(a => a.id === auditId);
    if (!audit) {
      return res.status(404).json({ error: 'Audit not found' });
    }

    const creator = users.find(u => u.id === audit.createdBy);

    // Create formatted audit report
    const auditReport = [
      ['PAKPRO DIGITAL VERIFICATION AUDIT REPORT'],
      [''],
      ['Audit ID:', audit.id],
      ['Status:', audit.status],
      ['Created By:', creator ? creator.fullName : 'Unknown'],
      ['Created Date:', new Date(audit.createdAt).toLocaleDateString()],
      [''],
      ['GENERAL INFORMATION'],
      ['Entity Name:', audit.entityName],
      ['Contract Reference:', audit.contractRef],
      ['Entity Address:', audit.generalInfo?.entityAddress || ''],
      ['Verification Period:', audit.generalInfo?.verificationPeriod || ''],
      ['Project Title:', audit.generalInfo?.projectTitle || ''],
      ['Auditee Team Leader:', audit.generalInfo?.auditeeTeamLeader || ''],
      ['Start Date:', audit.generalInfo?.startDate || ''],
      ['On-site Assessment Date:', audit.generalInfo?.onSiteDate || ''],
      [''],
      ['VALIDATION AND VERIFICATION'],
      ['Spot-checks conducted by PAKPRO:', audit.validation?.spotChecks || ''],
      ['Rejected post-consumer material:', audit.validation?.rejectedMaterial || ''],
      ['Rejection Details:', audit.validation?.rejectionDetails || ''],
      ['Contract amendments to be captured:', audit.validation?.contractAmendments || ''],
      ['Amendment Details:', audit.validation?.amendmentDetails || ''],
      ['Additional Comments:', audit.validation?.additionalComments || ''],
      [''],
      ['CONCLUSIONS'],
      ['Assessment Status:', audit.conclusions?.assessmentStatus || ''],
      ['PAKPRO Audit Team Leader:', audit.conclusions?.auditTeamLeader || ''],
      ['Audit Date:', audit.conclusions?.auditDate || ''],
      ['Additional Comments:', audit.conclusions?.conclusionComments || '']
    ];

    const workbook = XLSX.utils.book_new();
    const worksheet = XLSX.utils.aoa_to_sheet(auditReport);
    worksheet['!cols'] = [{ wch: 30 }, { wch: 50 }];
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Audit Report');

    const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

    res.setHeader('Content-Disposition', `attachment; filename=PAKPRO_Audit_${audit.id}.xlsx`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

    res.send(buffer);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Failed to export audit' });
  }
});

// Get current user info
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const users = await readJsonFile(USERS_FILE, []);
    const user = users.find(u => u.id === req.user.userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ 
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        fullName: user.fullName,
        department: user.department,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Initialize and start server
async function startServer() {
  try {
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`PAKPRO Audit Server running on port ${PORT}`);
      console.log(`Access the application at: http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();