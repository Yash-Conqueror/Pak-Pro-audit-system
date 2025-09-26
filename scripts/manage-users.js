#!/usr/bin/env node

// ========================================
// PAKPRO Enhanced User Management Script
// Manage users from command line
// ========================================

const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const readline = require('readline');

const CONFIG = {
    DATABASE_PATH: './data/pakpro_enhanced.db',
    BCRYPT_ROUNDS: 12
};

class UserManager {
    constructor() {
        this.db = null;
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
    }

    async connect() {
        return new Promise((resolve, reject) => {
            this.db = new sqlite3.Database(CONFIG.DATABASE_PATH, (err) => {
                if (err) {
                    console.error('❌ Database connection failed:', err.message);
                    reject(err);
                } else {
                    console.log('✅ Connected to database');
                    resolve();
                }
            });
        });
    }

    async close() {
        return new Promise((resolve) => {
            this.db.close((err) => {
                if (err) {
                    console.error('Error closing database:', err);
                }
                this.rl.close();
                resolve();
            });
        });
    }

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
                if (err) {
                    reject(err);
                } else {
                    resolve(row);
                }
            });
        });
    }

    async all(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows);
                }
            });
        });
    }

    question(prompt) {
        return new Promise((resolve) => {
            this.rl.question(prompt, resolve);
        });
    }

    async listUsers() {
        try {
            console.log('\n📋 Current Users:');
            console.log(''.padEnd(80, '='));
            
            const users = await this.all(`
                SELECT id, username, email, role, full_name, department, is_active, 
                       created_at, last_login
                FROM users 
                ORDER BY id
            `);

            if (users.length === 0) {
                console.log('No users found.');
                return;
            }

            console.log('ID'.padEnd(4) + 'Username'.padEnd(15) + 'Email'.padEnd(25) + 'Role'.padEnd(15) + 'Active'.padEnd(8) + 'Last Login');
            console.log(''.padEnd(80, '-'));

            users.forEach(user => {
                const lastLogin = user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never';
                const active = user.is_active ? '✅ Yes' : '❌ No';
                
                console.log(
                    user.id.toString().padEnd(4) +
                    user.username.padEnd(15) +
                    user.email.padEnd(25) +
                    user.role.padEnd(15) +
                    active.padEnd(8) +
                    lastLogin
                );
            });

        } catch (error) {
            console.error('❌ Error listing users:', error.message);
        }
    }

    async createUser() {
        try {
            console.log('\n➕ Create New User');
            console.log(''.padEnd(30, '='));

            const username = await this.question('Username: ');
            if (!username.trim()) {
                throw new Error('Username is required');
            }

            // Check if username exists
            const existingUser = await this.get('SELECT id FROM users WHERE username = ?', [username]);
            if (existingUser) {
                throw new Error('Username already exists');
            }

            const email = await this.question('Email: ');
            if (!email.trim()) {
                throw new Error('Email is required');
            }

            // Check if email exists
            const existingEmail = await this.get('SELECT id FROM users WHERE email = ?', [email]);
            if (existingEmail) {
                throw new Error('Email already exists');
            }

            const password = await this.question('Password: ');
            if (!password.trim() || password.length < 6) {
                throw new Error('Password must be at least 6 characters');
            }

            console.log('\nAvailable roles:');
            console.log('1. data_analyst    - Full access to all features');
            console.log('2. field_auditor   - Limited access, can only edit own audits');
            console.log('3. viewer          - Read-only access');
            
            const roleChoice = await this.question('Select role (1-3): ');
            let role;
            switch (roleChoice) {
                case '1': role = 'data_analyst'; break;
                case '2': role = 'field_auditor'; break;
                case '3': role = 'viewer'; break;
                default: throw new Error('Invalid role selection');
            }

            const fullName = await this.question('Full Name (optional): ');
            const department = await this.question('Department (optional): ');

            // Hash password
            const passwordHash = await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS);

            // Create user
            const result = await this.run(`
                INSERT INTO users (username, email, password_hash, role, full_name, department, is_active)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            `, [username, email, passwordHash, role, fullName || null, department || null]);

            console.log(`✅ User created successfully with ID: ${result.id}`);
            console.log(`   Username: ${username}`);
            console.log(`   Email: ${email}`);
            console.log(`   Role: ${role}`);

        } catch (error) {
            console.error('❌ Error creating user:', error.message);
        }
    }

    async updateUser() {
        try {
            console.log('\n✏️  Update User');
            console.log(''.padEnd(30, '='));

            await this.listUsers();
            
            const userId = await this.question('\nEnter User ID to update: ');
            if (!userId || isNaN(userId)) {
                throw new Error('Valid User ID is required');
            }

            const user = await this.get('SELECT * FROM users WHERE id = ?', [userId]);
            if (!user) {
                throw new Error('User not found');
            }

            console.log(`\nUpdating user: ${user.username} (${user.email})`);
            console.log('Leave blank to keep current value\n');

            const newEmail = await this.question(`Email (current: ${user.email}): `);
            const newFullName = await this.question(`Full Name (current: ${user.full_name || 'None'}): `);
            const newDepartment = await this.question(`Department (current: ${user.department || 'None'}): `);

            console.log('\nChange role?');
            console.log('1. data_analyst');
            console.log('2. field_auditor'); 
            console.log('3. viewer');
            console.log('4. Keep current (' + user.role + ')');
            
            const roleChoice = await this.question('Select option (1-4): ');
            let newRole = user.role;
            switch (roleChoice) {
                case '1': newRole = 'data_analyst'; break;
                case '2': newRole = 'field_auditor'; break;
                case '3': newRole = 'viewer'; break;
                case '4': break;
                default: console.log('Keeping current role');
            }

            const newPassword = await this.question('New Password (leave blank to keep current): ');

            // Build update query
            const updates = [];
            const params = [];

            if (newEmail.trim()) {
                updates.push('email = ?');
                params.push(newEmail.trim());
            }

            if (newFullName.trim()) {
                updates.push('full_name = ?');
                params.push(newFullName.trim());
            }

            if (newDepartment.trim()) {
                updates.push('department = ?');
                params.push(newDepartment.trim());
            }

            if (newRole !== user.role) {
                updates.push('role = ?');
                params.push(newRole);
            }

            if (newPassword.trim()) {
                const passwordHash = await bcrypt.hash(newPassword, CONFIG.BCRYPT_ROUNDS);
                updates.push('password_hash = ?');
                params.push(passwordHash);
            }

            if (updates.length === 0) {
                console.log('No changes made.');
                return;
            }

            updates.push('updated_at = CURRENT_TIMESTAMP');
            params.push(userId);

            await this.run(`
                UPDATE users 
                SET ${updates.join(', ')}
                WHERE id = ?
            `, params);

            console.log('✅ User updated successfully');

        } catch (error) {
            console.error('❌ Error updating user:', error.message);
        }
    }

    async deactivateUser() {
        try {
            console.log('\n🚫 Deactivate User');
            console.log(''.padEnd(30, '='));

            await this.listUsers();
            
            const userId = await this.question('\nEnter User ID to deactivate: ');
            if (!userId || isNaN(userId)) {
                throw new Error('Valid User ID is required');
            }

            const user = await this.get('SELECT * FROM users WHERE id = ?', [userId]);
            if (!user) {
                throw new Error('User not found');
            }

            if (!user.is_active) {
                console.log('User is already deactivated.');
                return;
            }

            const confirm = await this.question(`Deactivate user "${user.username}"? (y/N): `);
            if (confirm.toLowerCase() !== 'y') {
                console.log('Operation cancelled.');
                return;
            }

            await this.run('UPDATE users SET is_active = 0 WHERE id = ?', [userId]);
            console.log('✅ User deactivated successfully');

        } catch (error) {
            console.error('❌ Error deactivating user:', error.message);
        }
    }

    async reactivateUser() {
        try {
            console.log('\n✅ Reactivate User');
            console.log(''.padEnd(30, '='));

            const inactiveUsers = await this.all('SELECT * FROM users WHERE is_active = 0');
            
            if (inactiveUsers.length === 0) {
                console.log('No inactive users found.');
                return;
            }

            console.log('Inactive Users:');
            inactiveUsers.forEach(user => {
                console.log(`${user.id}: ${user.username} (${user.email})`);
            });
            
            const userId = await this.question('\nEnter User ID to reactivate: ');
            if (!userId || isNaN(userId)) {
                throw new Error('Valid User ID is required');
            }

            const user = await this.get('SELECT * FROM users WHERE id = ? AND is_active = 0', [userId]);
            if (!user) {
                throw new Error('Inactive user not found');
            }

            await this.run('UPDATE users SET is_active = 1 WHERE id = ?', [userId]);
            console.log('✅ User reactivated successfully');

        } catch (error) {
            console.error('❌ Error reactivating user:', error.message);
        }
    }

    async deleteUser() {
        try {
            console.log('\n🗑️  Delete User (PERMANENT)');
            console.log(''.padEnd(30, '='));
            console.log('⚠️  WARNING: This will permanently delete the user and all related data!');

            await this.listUsers();
            
            const userId = await this.question('\nEnter User ID to DELETE: ');
            if (!userId || isNaN(userId)) {
                throw new Error('Valid User ID is required');
            }

            const user = await this.get('SELECT * FROM users WHERE id = ?', [userId]);
            if (!user) {
                throw new Error('User not found');
            }

            console.log(`\n⚠️  You are about to PERMANENTLY DELETE:`);
            console.log(`   Username: ${user.username}`);
            console.log(`   Email: ${user.email}`);
            console.log(`   Role: ${user.role}`);

            const confirm1 = await this.question('\nType "DELETE" to confirm: ');
            if (confirm1 !== 'DELETE') {
                console.log('Operation cancelled.');
                return;
            }

            const confirm2 = await this.question('Are you absolutely sure? (yes/no): ');
            if (confirm2.toLowerCase() !== 'yes') {
                console.log('Operation cancelled.');
                return;
            }

            // Check if user has audits
            const auditCount = await this.get('SELECT COUNT(*) as count FROM audits WHERE created_by = ?', [userId]);
            if (auditCount.count > 0) {
                console.log(`\n⚠️  This user has ${auditCount.count} audits. These will be orphaned (created_by will be set to NULL).`);
                const proceedWithAudits = await this.question('Continue? (yes/no): ');
                if (proceedWithAudits.toLowerCase() !== 'yes') {
                    console.log('Operation cancelled.');
                    return;
                }

                // Update audits to remove reference
                await this.run('UPDATE audits SET created_by = NULL WHERE created_by = ?', [userId]);
            }

            // Delete user
            await this.run('DELETE FROM users WHERE id = ?', [userId]);
            console.log('✅ User deleted successfully');

        } catch (error) {
            console.error('❌ Error deleting user:', error.message);
        }
    }

    async resetPassword() {
        try {
            console.log('\n🔑 Reset User Password');
            console.log(''.padEnd(30, '='));

            await this.listUsers();
            
            const userId = await this.question('\nEnter User ID to reset password: ');
            if (!userId || isNaN(userId)) {
                throw new Error('Valid User ID is required');
            }

            const user = await this.get('SELECT * FROM users WHERE id = ?', [userId]);
            if (!user) {
                throw new Error('User not found');
            }

            console.log(`Resetting password for: ${user.username} (${user.email})`);

            const newPassword = await this.question('New Password: ');
            if (!newPassword.trim() || newPassword.length < 6) {
                throw new Error('Password must be at least 6 characters');
            }

            const confirmPassword = await this.question('Confirm Password: ');
            if (newPassword !== confirmPassword) {
                throw new Error('Passwords do not match');
            }

            const passwordHash = await bcrypt.hash(newPassword, CONFIG.BCRYPT_ROUNDS);
            
            await this.run(`
                UPDATE users 
                SET password_hash = ?, login_attempts = 0, locked_until = NULL 
                WHERE id = ?
            `, [passwordHash, userId]);

            console.log('✅ Password reset successfully');
            console.log('✅ Login attempts cleared and account unlocked');

        } catch (error) {
            console.error('❌ Error resetting password:', error.message);
        }
    }

    async showMenu() {
        console.log('\n🎯 PAKPRO User Management');
        console.log(''.padEnd(30, '='));
        console.log('1. List all users');
        console.log('2. Create new user');
        console.log('3. Update user');
        console.log('4. Deactivate user');
        console.log('5. Reactivate user');
        console.log('6. Reset password');
        console.log('7. Delete user (permanent)');
        console.log('8. Exit');
        console.log('');

        const choice = await this.question('Select option (1-8): ');
        return choice;
    }

    async run() {
        try {
            await this.connect();

            console.log('🎯 PAKPRO Enhanced User Management System');
            console.log('Database:', CONFIG.DATABASE_PATH);

            while (true) {
                const choice = await this.showMenu();

                switch (choice) {
                    case '1':
                        await this.listUsers();
                        break;
                    case '2':
                        await this.createUser();
                        break;
                    case '3':
                        await this.updateUser();
                        break;
                    case '4':
                        await this.deactivateUser();
                        break;
                    case '5':
                        await this.reactivateUser();
                        break;
                    case '6':
                        await this.resetPassword();
                        break;
                    case '7':
                        await this.deleteUser();
                        break;
                    case '8':
                        console.log('👋 Goodbye!');
                        return;
                    default:
                        console.log('Invalid option. Please try again.');
                }

                if (choice !== '8') {
                    await this.question('\nPress Enter to continue...');
                }
            }

        } catch (error) {
            console.error('❌ Fatal error:', error.message);
        } finally {
            await this.close();
        }
    }
}

// Command line argument handling
if (require.main === module) {
    const args = process.argv.slice(2);
    
    if (args.length > 0) {
        console.log('Usage: node scripts/manage-users.js');
        console.log('This script provides an interactive menu for user management.');
        process.exit(1);
    }

    const userManager = new UserManager();
    userManager.run();
}

module.exports = UserManager;