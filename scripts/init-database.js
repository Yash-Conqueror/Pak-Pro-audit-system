const path = require('path');
const fs = require('fs').promises;
const sqlite3 = require('sqlite3').verbose();

async function initializeDatabase() {
  try {
    console.log('🗄️  Initializing PAKPRO Enhanced Database...');
    
    // Ensure data directory exists
    await fs.mkdir('./data', { recursive: true });
    
    const db = new sqlite3.Database('./data/pakpro_enhanced.db');
    
    console.log('✅ Database file created successfully');
    console.log('✅ Database initialization completed');
    
    db.close();
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
}

initializeDatabase();
