const fs = require('fs').promises;
const path = require('path');
const archiver = require('archiver');

async function createBackup() {
  try {
    console.log('💾 Creating database backup...');
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFile = path.join('./backups', `pakpro_backup_${timestamp}.zip`);
    
    // Ensure backup directory exists
    await fs.mkdir('./backups', { recursive: true });
    
    const output = require('fs').createWriteStream(backupFile);
    const archive = archiver('zip', { zlib: { level: 9 } });
    
    archive.pipe(output);
    archive.directory('./data', 'data');
    archive.directory('./logs', 'logs');
    await archive.finalize();
    
    console.log(`✅ Backup created: ${backupFile}`);
  } catch (error) {
    console.error('❌ Backup creation failed:', error);
    process.exit(1);
  }
}

createBackup();
