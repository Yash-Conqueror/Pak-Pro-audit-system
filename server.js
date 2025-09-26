// ========================================
// PAKPRO Kenya Digital Verification Audit System
// Backend Server - Simplified Version
// Version: 2.0.0 Kenya Edition
// ========================================

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs').promises;
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');


// ========================================
// CONFIGURATION - KENYA
// ========================================
const CONFIG = {
    PORT: process.env.PORT || 3000,
    JWT_SECRET: process.env.JWT_SECRET || 'pakpro_kenya_secret_2024',
    JWT_EXPIRES_IN: '24h',
    DATABASE_PATH: './data/pakpro_kenya.db',
    COUNTRY: 'Kenya',
    CURRENCY: 'KES'
};

// Kenyan Counties for validation
const KENYAN_COUNTIES = [
    'Nairobi County', 'Mombasa County', 'Kisumu County', 'Nakuru County',
    'Kiambu County', 'Machakos County', 'Kajiado County', 'Kilifi County',
    'Uasin Gishu County', 'Kakamega County', 'Meru County', 'Nyeri County',
    'Kericho County', 'Murang\'a County', 'Laikipia County'
];

// ========================================
// DATABASE SETUP
// ========================================
class Database {
    constructor() {
        this.db = null;
    }

    async initialize() {
        try {
            // Ensure data directory exists
            await fs.mkdir('./data', { recursive: true });
            
            this.db = new sqlite3.Database(CONFIG.DATABASE_PATH);
            
            // Enable foreign keys
            this.db.run('PRAGMA foreign_keys = ON');
            
            await this.createTables();
            await this.seedDefaultData();
            
            console.log('✅ Database initialized successfully');
        } catch (error) {
            console.error('❌ Database initialization failed:', error);
            throw error;
        }
    }

    async createTables() {
        const tables = [
            // Users table
            `CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) DEFAULT 'field_auditor',
                full_name VARCHAR(100),
                county VARCHAR(50),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,

            // Audits table for Kenya
            `CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_name VARCHAR(200) NOT NULL,
                contract_ref VARCHAR(100) NOT NULL,
                status VARCHAR(20) DEFAULT 'draft',
                procurement_location VARCHAR(100),
                processing_location VARCHAR(100),
                verification_period_start DATE,
                verification_period_end DATE,
                project_title VARCHAR(200),
                auditee_team_leader VARCHAR(100),
                auditee_team_members TEXT,
                purchased_volume DECIMAL(15,2),
                processed_volume DECIMAL(15,2),
                rejected_volume DECIMAL(15,2),
                audited_volume DECIMAL(15,2),
                contract_limit DECIMAL(15,2),
                subsidized_volume DECIMAL(15,2),
                cpaf_rate DECIMAL(10,2),
                cpaf_payable DECIMAL(15,2),
                source_county VARCHAR(100),
                osh_act_compliance BOOLEAN DEFAULT 0,
                ppe_compliance BOOLEAN DEFAULT 0,
                environmental_audits BOOLEAN DEFAULT 0,
                additional_notes TEXT,
                pakpro_ceo_signature TEXT,
                recycler_signature TEXT,
                auditor_signature TEXT,
                completion_percentage INTEGER DEFAULT 0,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )`
        ];

        for (const sql of tables) {
            await this.run(sql);
        }
    }

    async seedDefaultData() {
        // Check if users exist
        const userCount = await this.get('SELECT COUNT(*) as count FROM users');
        
        if (userCount.count === 0) {
            console.log('🌱 Seeding default users for Kenya...');
            
            const defaultUsers = [
                {
                    username: 'admin',
                    email: 'admin@pakpro.co.ke',
                    password: 'pakpro123',
                    role: 'data_analyst',
                    full_name: 'System Administrator',
                    county: 'Nairobi County'
                },
                {
                    username: 'analyst1',
                    email: 'analyst1@pakpro.co.ke',
                    password: 'analyst123',
                    role: 'data_analyst',
                    full_name: 'Senior Data Analyst',
                    county: 'Nairobi County'
                }
            ];

            for (const user of defaultUsers) {
                const hashedPassword = await bcrypt.hash(user.password, 12);
                await this.run(`
                    INSERT INTO users (username, email, password_hash, role, full_name, county)
                    VALUES (?, ?, ?, ?, ?, ?)
                `, [user.username, user.email, hashedPassword, user.role, user.full_name, user.county]);
            }
        }

        // Seed demo audit data for Kenya
        const auditCount = await this.get('SELECT COUNT(*) as count FROM audits');
        
        if (auditCount.count === 0) {
            console.log('🌱 Seeding demo audit data for Kenya...');
            
            const demoAudits = [
                {
                    entity_name: 'Eco Post Kenya Limited',
                    contract_ref: 'CT-KE-2024-001',
                    status: 'finalized',
                    procurement_location: 'Nairobi County',
                    processing_location: 'Nairobi County',
                    project_title: 'Plastic Waste Recycling Initiative Phase 1',
                    purchased_volume: 1000.50,
                    processed_volume: 950.25,
                    rejected_volume: 50.25,
                    audited_volume: 900.00,
                    contract_limit: 750000.00,
                    subsidized_volume: 800.00,
                    cpaf_rate: 150.00,
                    cpaf_payable: 120000.00,
                    source_county: 'Nairobi County',
                    osh_act_compliance: 1,
                    ppe_compliance: 1,
                    environmental_audits: 1,
                    completion_percentage: 100,
                    created_by: 1
                },
                {
                    entity_name: 'Green Cycle Industries Kenya Ltd',
                    contract_ref: 'CT-KE-2024-002',
                    status: 'pending',
                    procurement_location: 'Mombasa County',
                    processing_location: 'Mombasa County',
                    project_title: 'Coastal Plastic Recovery Project',
                    purchased_volume: 750.75,
                    processed_volume: 720.50,
                    rejected_volume: 30.25,
                    audited_volume: 690.25,
                    contract_limit: 525000.00,
                    subsidized_volume: 600.00,
                    cpaf_rate: 140.00,
                    cpaf_payable: 84000.00,
                    source_county: 'Mombasa County',
                    osh_act_compliance: 1,
                    ppe_compliance: 0,
                    environmental_audits: 1,
                    completion_percentage: 75,
                    created_by: 2
                },
                {
                    entity_name: 'Nakuru Waste Management Solutions',
                    contract_ref: 'CT-KE-2024-003',
                    status: 'draft',
                    procurement_location: 'Nakuru County',
                    processing_location: 'Nakuru County',
                    project_title: 'Rift Valley Recycling Hub',
                    purchased_volume: 1200.00,
                    processed_volume: 1150.75,
                    rejected_volume: 25.00,
                    audited_volume: 1125.75,
                    contract_limit: 900000.00,
                    subsidized_volume: 1000.00,
                    cpaf_rate: 160.00,
                    cpaf_payable: 160000.00,
                    source_county: 'Nakuru County',
                    osh_act_compliance: 0,
                    ppe_compliance: 1,
                    environmental_audits: 0,
                    completion_percentage: 45,
                    created_by: 1
                }
            ];

            for (const audit of demoAudits) {
                await this.run(`
                    INSERT INTO audits (
                        entity_name, contract_ref, status, procurement_location, processing_location,
                        project_title, purchased_volume, processed_volume, rejected_volume, audited_volume,
                        contract_limit, subsidized_volume, cpaf_rate, cpaf_payable, source_county,
                        osh_act_compliance, ppe_compliance, environmental_audits, completion_percentage, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [
                    audit.entity_name, audit.contract_ref, audit.status, audit.procurement_location,
                    audit.processing_location, audit.project_title, audit.purchased_volume,
                    audit.processed_volume, audit.rejected_volume, audit.audited_volume,
                    audit.contract_limit, audit.subsidized_volume, audit.cpaf_rate,
                    audit.cpaf_payable, audit.source_county, audit.osh_act_compliance,
                    audit.ppe_compliance, audit.environmental_audits, audit.completion_percentage, audit.created_by
                ]);
            }
        }
    }

    // Database operation helpers
    async run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) {
                    reject(err);
                } else {
                    resolve({ id: this.lastID, changes: this.changes });
                }
            });
        });
    }

    async get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    async all(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }
}

// ========================================
// MIDDLEWARE
// ========================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    jwt.verify(token, CONFIG.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000 // limit each IP to 1000 requests per windowMs
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5 // limit each IP to 5 requests per windowMs
});

// ========================================
// EXPRESS APP SETUP
// ========================================
const app = express();
const db = new Database();

// Trust proxy configuration (required for rate limiting behind proxies/load balancers)
app.set('trust proxy', true);

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'"]
        }
    }
}));

app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// ========================================
// AUTH ROUTES
// ========================================
app.post('/api/v1/auth/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password required'
            });
        }

        const user = await db.get(`
            SELECT * FROM users 
            WHERE username = ? OR email = ?
        `, [username, username]);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const token = jwt.sign(
            { 
                userId: user.id, 
                username: user.username, 
                role: user.role,
                county: user.county
            },
            CONFIG.JWT_SECRET,
            { expiresIn: CONFIG.JWT_EXPIRES_IN }
        );

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                full_name: user.full_name,
                county: user.county
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// ========================================
// AUDIT ROUTES
// ========================================
app.get('/api/v1/audits', authenticateToken, async (req, res) => {
    try {
        const { status, entityName, county, page = 1, limit = 50 } = req.query;

        let whereClause = '1=1';
        const params = [];

        if (status) {
            whereClause += ' AND status = ?';
            params.push(status);
        }

        if (entityName) {
            whereClause += ' AND entity_name LIKE ?';
            params.push(`%${entityName}%`);
        }

        if (county) {
            whereClause += ' AND source_county = ?';
            params.push(county);
        }

        const offset = (page - 1) * limit;

        const audits = await db.all(`
            SELECT 
                a.*,
                u.full_name as created_by_name
            FROM audits a
            LEFT JOIN users u ON a.created_by = u.id
            WHERE ${whereClause}
            ORDER BY a.created_at DESC
            LIMIT ? OFFSET ?
        `, [...params, limit, offset]);

        const totalResult = await db.get(`
            SELECT COUNT(*) as total 
            FROM audits 
            WHERE ${whereClause}
        `, params);

        res.json({
            success: true,
            data: audits,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: totalResult.total,
                pages: Math.ceil(totalResult.total / limit)
            }
        });

    } catch (error) {
        console.error('Error fetching audits:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch audits'
        });
    }
});

app.post('/api/v1/audits', authenticateToken, async (req, res) => {
    try {
        const auditData = req.body;
        
        // Calculate completion percentage
        const completion = calculateCompletionPercentage(auditData);
        
        const result = await db.run(`
            INSERT INTO audits (
                entity_name, contract_ref, status, procurement_location, processing_location,
                verification_period_start, verification_period_end, project_title, auditee_team_leader,
                auditee_team_members, purchased_volume, processed_volume, rejected_volume,
                audited_volume, contract_limit, subsidized_volume, cpaf_rate, cpaf_payable,
                source_county, osh_act_compliance, ppe_compliance, environmental_audits,
                additional_notes, pakpro_ceo_signature, recycler_signature, auditor_signature,
                completion_percentage, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            auditData.entityName, auditData.contractRef, auditData.status || 'draft',
            auditData.procurementLocation, auditData.processingLocation,
            auditData.verificationPeriodStart, auditData.verificationPeriodEnd,
            auditData.projectTitle, auditData.auditeeTeamLeader, auditData.auditeeTeamMembers,
            auditData.purchasedVolume, auditData.processedVolume, auditData.rejectedVolume,
            auditData.auditedVolume, auditData.contractLimit, auditData.subsidizedVolume,
            auditData.cpafRate, auditData.cpafPayable, auditData.sourceCounty,
            auditData.oshActCompliance ? 1 : 0, auditData.ppeCompliance ? 1 : 0,
            auditData.environmentalAudits ? 1 : 0, auditData.additionalNotes,
            auditData.pakproCeoSignature, auditData.recyclerSignature, auditData.auditorSignature,
            completion, req.user.userId
        ]);

        const newAudit = await db.get('SELECT * FROM audits WHERE id = ?', [result.id]);

        res.status(201).json({
            success: true,
            message: 'Audit created successfully',
            data: newAudit
        });

    } catch (error) {
        console.error('Error creating audit:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create audit'
        });
    }
});

app.put('/api/v1/audits/:id', authenticateToken, async (req, res) => {
    try {
        const auditId = req.params.id;
        const auditData = req.body;

        // Check if audit exists
        const existingAudit = await db.get('SELECT * FROM audits WHERE id = ?', [auditId]);
        
        if (!existingAudit) {
            return res.status(404).json({
                success: false,
                message: 'Audit not found'
            });
        }

        const completion = calculateCompletionPercentage(auditData);

        await db.run(`
            UPDATE audits 
            SET entity_name = ?, contract_ref = ?, status = ?, procurement_location = ?,
                processing_location = ?, project_title = ?, purchased_volume = ?,
                processed_volume = ?, rejected_volume = ?, audited_volume = ?,
                contract_limit = ?, subsidized_volume = ?, cpaf_rate = ?, cpaf_payable = ?,
                source_county = ?, additional_notes = ?, completion_percentage = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `, [
            auditData.entityName, auditData.contractRef, auditData.status,
            auditData.procurementLocation, auditData.processingLocation,
            auditData.projectTitle, auditData.purchasedVolume, auditData.processedVolume,
            auditData.rejectedVolume, auditData.auditedVolume, auditData.contractLimit,
            auditData.subsidizedVolume, auditData.cpafRate, auditData.cpafPayable,
            auditData.sourceCounty, auditData.additionalNotes, completion, auditId
        ]);

        const updatedAudit = await db.get('SELECT * FROM audits WHERE id = ?', [auditId]);

        res.json({
            success: true,
            message: 'Audit updated successfully',
            data: updatedAudit
        });

    } catch (error) {
        console.error('Error updating audit:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update audit'
        });
    }
});

app.delete('/api/v1/audits/:id', authenticateToken, async (req, res) => {
    try {
        const auditId = req.params.id;

        const audit = await db.get('SELECT * FROM audits WHERE id = ?', [auditId]);
        
        if (!audit) {
            return res.status(404).json({
                success: false,
                message: 'Audit not found'
            });
        }

        await db.run('DELETE FROM audits WHERE id = ?', [auditId]);

        res.json({
            success: true,
            message: 'Audit deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting audit:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete audit'
        });
    }
});

// Get specific audit
app.get('/api/v1/audits/:id', authenticateToken, async (req, res) => {
    try {
        const auditId = req.params.id;

        const audit = await db.get(`
            SELECT 
                a.*,
                u.full_name as created_by_name
            FROM audits a
            LEFT JOIN users u ON a.created_by = u.id
            WHERE a.id = ?
        `, [auditId]);

        if (!audit) {
            return res.status(404).json({
                success: false,
                message: 'Audit not found'
            });
        }

        res.json({
            success: true,
            data: audit
        });

    } catch (error) {
        console.error('Error fetching audit:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch audit'
        });
    }
});

// ========================================
// ANALYTICS ROUTES
// ========================================
app.get('/api/v1/analytics/dashboard', authenticateToken, async (req, res) => {
    try {
        const stats = await calculateDashboardStats();
        
        res.json({
            success: true,
            data: stats,
            currency: CONFIG.CURRENCY,
            country: CONFIG.COUNTRY
        });

    } catch (error) {
        console.error('Error fetching dashboard analytics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch dashboard analytics'
        });
    }
});

async function calculateDashboardStats() {
    const totalAudits = await db.get('SELECT COUNT(*) as count FROM audits');
    const finalizedAudits = await db.get('SELECT COUNT(*) as count FROM audits WHERE status = "finalized"');
    const pendingAudits = await db.get('SELECT COUNT(*) as count FROM audits WHERE status = "pending"');
    const draftAudits = await db.get('SELECT COUNT(*) as count FROM audits WHERE status = "draft"');
    
    const volumeStats = await db.get(`
        SELECT 
            SUM(purchased_volume) as total_purchased,
            SUM(processed_volume) as total_processed,
            SUM(rejected_volume) as total_rejected,
            SUM(subsidized_volume) as total_subsidized,
            SUM(cpaf_payable) as total_cpaf_payable,
            AVG(completion_percentage) as avg_completion
        FROM audits
    `);

    return {
        totalAudits: totalAudits.count,
        finalizedAudits: finalizedAudits.count,
        pendingAudits: pendingAudits.count,
        draftAudits: draftAudits.count,
        totalRejectedVolume: volumeStats.total_rejected || 0,
        totalCPAFPayable: volumeStats.total_cpaf_payable || 0,
        totalSubsidizedVolume: volumeStats.total_subsidized || 0,
        avgCompletion: Math.round(volumeStats.avg_completion || 0)
    };
}

// Get Kenya counties
app.get('/api/v1/counties', (req, res) => {
    res.json({
        success: true,
        data: KENYAN_COUNTIES,
        total: KENYAN_COUNTIES.length
    });
});

// ========================================
// UTILITY FUNCTIONS
// ========================================
function calculateCompletionPercentage(auditData) {
    const requiredFields = [
        'entityName', 'contractRef', 'procurementLocation', 'processingLocation',
        'projectTitle', 'purchasedVolume', 'processedVolume', 'auditedVolume',
        'contractLimit', 'subsidizedVolume', 'cpafPayable', 'sourceCounty'
    ];
    
    let completedFields = 0;
    for (const field of requiredFields) {
        if (auditData[field] && auditData[field].toString().trim() !== '') {
            completedFields++;
        }
    }
    
    return Math.round((completedFields / requiredFields.length) * 100);
}

// ========================================
// ERROR HANDLING
// ========================================
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

// ========================================
// SERVER STARTUP
// ========================================
async function startServer() {
    try {
        await db.initialize();
        
        const port = CONFIG.PORT;
        app.listen(port, () => {
            console.log(`
🎯 PAKPRO Kenya Digital Verification Audit System
✅ Server running on http://localhost:${port}
✅ Database connected and initialized
🇰🇪 Supporting ${KENYAN_COUNTIES.length} Kenyan counties
💰 Currency: KSh (${CONFIG.CURRENCY})
            `);
        });

        // Graceful shutdown
        process.on('SIGINT', async () => {
            console.log('Shutting down server...');
            process.exit(0);
        });

    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();