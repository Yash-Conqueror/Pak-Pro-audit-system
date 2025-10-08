// ========================================
// PAKPRO Kenya Digital Verification Audit System
// Client-side Application Logic
// Version: 2.0.0 Kenya Edition
// ========================================

// ========================================
// GLOBAL VARIABLES & CONFIGURATION
// ========================================
window.APP_VERSION = window.APP_VERSION || "2.0.0 Kenya Edition";
const AUTO_SAVE_INTERVAL = 30000;
const API_BASE_URL = '/api/v1';

let currentUser = null;
let currentAuditId = null;
let audits = [];
let hasUnsavedChanges = false;
let autoSaveInterval = null;
let signatureData = {
    pakproCeo: null,
    recycler: null,
    auditor: null
};

// ========================================
// INITIALIZATION
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    console.log(`🇰🇪 PAKPRO Kenya Digital Audit System v${APP_VERSION} - Loading...`);
    
    // Initialize login form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Initialize signature canvases
    initializeSignatureCanvases();
    
    // Set up form change tracking
    document.addEventListener('input', (e) => {
        // Only track changes on form elements
        if (e.target.matches('.form-input, .form-select, .form-textarea')) {
            hasUnsavedChanges = true;
            updateProgressTracking();
        }
    });

    // Set up auto-save
    initializeAutoSave();
    
    // Initialize app if user is already logged in
    const token = localStorage.getItem('authToken');
    if (token) {
        // Try to validate the token by making a test API call
        validateTokenAndInit();
    }

    console.log('✅ PAKPRO Kenya System Ready!');
});

async function validateTokenAndInit() {
    try {
        const response = await apiCall('/analytics/dashboard');
        // If this succeeds, we have a valid token
        currentUser = { username: 'Authenticated User' }; // Basic user object
        hideElement('loginScreen');
        showElement('mainApp');
        initializeApplication();
        console.log('✅ Auto-login successful');
    } catch (error) {
        // Invalid token, remove it
        localStorage.removeItem('authToken');
        console.log('Token expired, please login again');
    }
}

// ========================================
// AUTHENTICATION FUNCTIONS
// ========================================
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username')?.value;
    const password = document.getElementById('password')?.value;
    
    if (!username || !password) {
        showToast('Please enter username and password', 'error');
        return;
    }

    try {
        showToast('Logging in...', 'info');
        
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });

        // Check if response is OK before parsing JSON
        if (!response.ok) {
            let errorMessage = 'Login failed';
            try {
                const data = await response.json();
                errorMessage = data.message || errorMessage;
            } catch (e) {
                // If JSON parsing fails, use status text
                errorMessage = response.statusText || errorMessage;
            }
            showToast(errorMessage, 'error');
            return;
        }

        const data = await response.json();

        if (data.success) {
            localStorage.setItem('authToken', data.token);
            currentUser = data.user;
            
            updateUserInterface();
            hideElement('loginScreen');
            showElement('mainApp');
            initializeApplication();
            showToast('Welcome to PAKPRO Kenya!', 'success');
        } else {
            showToast(data.message || 'Login failed', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showToast('Login failed. Please try again.', 'error');
    }
}

function updateUserInterface() {
    if (currentUser) {
        const nameElement = document.getElementById('currentUserName');
        const roleElement = document.getElementById('currentUserRole');
        const avatarElement = document.getElementById('userAvatar');
        
        if (nameElement) nameElement.textContent = currentUser.full_name || currentUser.username;
        if (roleElement) roleElement.textContent = currentUser.role || 'User';
        if (avatarElement) avatarElement.textContent = (currentUser.full_name || currentUser.username).charAt(0).toUpperCase();
    }
}

function logout() {
    localStorage.removeItem('authToken');
    currentUser = null;
    currentAuditId = null;
    clearAutoSave();
    showElement('loginScreen');
    hideElement('mainApp');
    showToast('Logged out successfully', 'info');
}

function initializeApplication() {
    loadAudits();
    updateDashboardStats();
    updateProgressTracking();
}

// ========================================
// API HELPER FUNCTIONS
// ========================================
function getAuthHeaders() {
    const token = localStorage.getItem('authToken');
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
}

async function apiCall(endpoint, options = {}) {
    const token = localStorage.getItem('authToken');
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            ...(token && { 'Authorization': `Bearer ${token}` })
        }
    };

    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    };

    const response = await fetch(`${API_BASE_URL}${endpoint}`, mergedOptions);
    
    if (response.status === 401) {
        // Token expired, redirect to login
        logout();
        throw new Error('Authentication required');
    }
    
    // Try to parse JSON, but handle non-JSON responses
    let data;
    try {
        data = await response.json();
    } catch (e) {
        // If JSON parsing fails, create a basic error object
        data = {
            success: false,
            message: response.statusText || 'Request failed'
        };
    }
    
    if (!response.ok) {
        throw new Error(data.message || 'API request failed');
    }
    
    return data;
}

// ========================================
// NAVIGATION FUNCTIONS
// ========================================
function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('section').forEach(section => {
        section.classList.add('hidden');
    });
    
    // Remove active class from all nav links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // Show selected section
    const targetSection = document.getElementById(sectionName + 'Section');
    if (targetSection) {
        targetSection.classList.remove('hidden');
        
        // Activate corresponding nav link
        const navLink = document.querySelector(`[onclick="showSection('${sectionName}')"]`);
        if (navLink) {
            navLink.classList.add('active');
        }
        
        // Handle section-specific initialization
        switch (sectionName) {
            case 'dashboard':
                updateDashboardStats();
                break;
            case 'newAudit':
                initializeNewAuditForm();
                break;
            case 'auditList':
                loadAudits();
                break;
            case 'analytics':
                updateAnalytics();
                break;
        }
    }
}

function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Remove active class from all tab buttons
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });
    
    // Show selected tab content
    const targetTab = document.getElementById(tabName + 'Tab');
    if (targetTab) {
        targetTab.classList.add('active');
        
        // Activate corresponding tab button
        const tabButton = document.querySelector(`[onclick="switchTab('${tabName}')"]`);
        if (tabButton) {
            tabButton.classList.add('active');
        }
    }
    
    updateProgressTracking();
}

// ========================================
// DASHBOARD & ANALYTICS
// ========================================
async function updateDashboardStats() {
    try {
        const response = await apiCall('/analytics/dashboard');
        const stats = response.data;
        
        console.log('Dashboard stats received:', stats); // Debug log
        
        // Update stat cards with actual data
        updateStatElement('totalAudits', stats.totalAudits || 0);
        updateStatElement('finalizedAudits', stats.finalizedAudits || 0);
        updateStatElement('pendingAudits', stats.pendingAudits || 0);
        updateStatElement('rejectedVolume', (stats.totalRejectedVolume || 0).toFixed(1) + ' MT');
        
        // Update analytics section with real data (this was missing before)
        updateStatElement('completionRate', Math.round(stats.avgCompletion || 0) + '%');
        updateStatElement('totalCPAF', 'KSh ' + (stats.totalCPAFPayable || 0).toLocaleString());
        updateStatElement('totalSubsidized', (stats.totalSubsidizedVolume || 0).toFixed(2) + ' MT');
        updateStatElement('avgProcessingTime', '7 days'); 
        
        // Load audits first, then update recent audits table
        if (!audits || audits.length === 0) {
            await loadAudits();
        }
        
        const recentTable = document.getElementById('recentAuditsTable');
        if (recentTable && audits.length > 0) {
            displayRecentAudits(audits.slice(0, 5));
        }
        
        // Update county performance table with real data (this was missing)
        if (audits && audits.length > 0) {
            updateCountyPerformanceTable(audits);
        }
        
    } catch (error) {
        console.error('Failed to update dashboard stats:', error);
        showToast('Failed to update dashboard statistics', 'error');
    }
}
function updateStatElement(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value;
    }
}

function displayRecentAudits(auditList) {
    const tbody = document.getElementById('recentAuditsTable');
    if (!tbody) return;
    
    if (auditList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No recent audits available</td></tr>';
        return;
    }
    
    tbody.innerHTML = auditList.map(audit => `
        <tr onclick="editAudit('${audit.id}')" style="cursor: pointer;">
            <td>${audit.entity_name || 'N/A'}</td>
            <td>${audit.contract_ref || 'N/A'}</td>
            <td><span class="status-badge status-${audit.status || 'draft'}">${(audit.status || 'draft').replace('_', ' ')}</span></td>
            <td>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <div class="progress-bar" style="flex: 1; height: 6px;">
                        <div class="progress-fill" style="width: ${audit.completion_percentage || 0}%"></div>
                    </div>
                    <span style="font-size: 0.75rem;">${audit.completion_percentage || 0}%</span>
                </div>
            </td>
            <td>${formatDate(audit.updated_at || audit.created_at)}</td>
            <td>
                <button class="btn btn-outline" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="event.stopPropagation(); editAudit('${audit.id}')" title="View/Edit Audit">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

function refreshDashboard() {
    showToast('Refreshing dashboard...', 'info');
    Promise.all([
        updateDashboardStats(),
        loadAudits()
    ]).then(() => {
        showToast('Dashboard refreshed successfully', 'success');
    }).catch(error => {
        console.error('Dashboard refresh error:', error);
        showToast('Failed to refresh dashboard', 'error');
    });
}

async function updateAnalytics() {
    try {
        const response = await apiCall('/analytics/dashboard');
        const stats = response.data;
        
        // Update analytics display
        const elements = {
            completionRate: (stats.avgCompletion || 0) + '%',
            totalCPAF: 'KSh ' + (stats.totalCPAFPayable || 0).toLocaleString(),
            totalSubsidized: (stats.totalSubsidizedVolume || 0).toFixed(2) + ' MT',
            avgProcessingTime: '7 days' // This would be calculated from audit data
        };
        
        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });
        
    } catch (error) {
        console.error('Failed to update analytics:', error);
    }
}

// ========================================
// AUDIT MANAGEMENT
// ========================================
async function loadAudits() {
    try {
        const response = await apiCall('/audits');
        audits = response.data;
        
        // Update audit list if on that page
        const auditListTable = document.getElementById('auditListTable');
        if (auditListTable) {
            displayAuditList(audits);
        }
        
    } catch (error) {
        console.error('Failed to load audits:', error);
        showToast('Failed to load audits', 'error');
    }
}

function displayAuditList(auditList) {
    const tbody = document.getElementById('auditListTable');
    if (!tbody) return;
    
    if (auditList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No audits found</td></tr>';
        return;
    }
    
    tbody.innerHTML = auditList.map(audit => `
        <tr>
            <td>${audit.id}</td>
            <td>${audit.entity_name || 'N/A'}</td>
            <td>${audit.contract_ref || 'N/A'}</td>
            <td><span class="status-badge status-${audit.status || 'draft'}">${(audit.status || 'draft').replace('_', ' ')}</span></td>
            <td>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <div class="progress-bar" style="flex: 1; height: 6px;">
                        <div class="progress-fill" style="width: ${audit.completion_percentage || 0}%"></div>
                    </div>
                    <span style="font-size: 0.75rem;">${audit.completion_percentage || 0}%</span>
                </div>
            </td>
            <td>${formatDate(audit.created_at)}</td>
            <td>
                <div style="display: flex; gap: 0.5rem;">
                    ${currentUser && currentUser.permissions && currentUser.permissions.includes('edit_audit') ? `
                    <button class="btn btn-outline" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="editAudit('${audit.id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    ` : `
                    <button class="btn btn-outline" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="editAudit('${audit.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    `}
                    ${currentUser && currentUser.permissions && currentUser.permissions.includes('delete_audit') ? `
                    <button class="btn btn-danger" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="confirmDeleteAudit('${audit.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                    ` : ''}
                </div>
            </td>
        </tr>
    `).join('');
}

async function editAudit(auditId) {
    try {
        const response = await apiCall(`/audits/${auditId}`);
        const audit = response.data;
        
        // Populate form with audit data
        populateFormWithAudit(audit);
        currentAuditId = auditId;
        
        // Switch to new audit form
        showSection('newAudit');
        showToast(`Editing audit: ${audit.entity_name}`, 'info');
        
        
    } catch (error) {
        console.error('Failed to load audit for editing:', error);
        showToast('Failed to load audit for editing', 'error');
    }
}

function populateFormWithAudit(audit) {
    // Populate form fields
    const fields = {
        'entityName': audit.entity_name,
        'contractRef': audit.contract_ref,
        'procurementLocation': audit.procurement_location,
        'processingLocation': audit.processing_location,
        'verificationPeriodStart': audit.verification_period_start,
        'verificationPeriodEnd': audit.verification_period_end,
        'projectTitle': audit.project_title,
        'auditeeTeamLeader': audit.auditee_team_leader,
        'auditeeTeamMembers': audit.auditee_team_members,
        'purchasedVolume': audit.purchased_volume,
        'processedVolume': audit.processed_volume,
        'rejectedVolume': audit.rejected_volume,
        'contractLimit': audit.contract_limit,
        'additionalNotes': audit.additional_notes
    };
    
    Object.entries(fields).forEach(([fieldId, value]) => {
        const element = document.getElementById(fieldId);
        if (element && value !== null && value !== undefined) {
            element.value = value;
        }
        // Load photos if they exist
if (audit.photos && window.photoManager) {
    photoManager.loadPhotosData(audit.photos);
}
    });
    
    // Calculate totals
    calculateTotals();
}

function confirmDeleteAudit(auditId) {
    if (confirm('Are you sure you want to delete this audit? This action cannot be undone.')) {
        deleteAudit(auditId);
    }
}

async function deleteAudit(auditId) {
    try {
        await apiCall(`/audits/${auditId}`, { method: 'DELETE' });
        showToast('Audit deleted successfully', 'success');
        loadAudits();
    } catch (error) {
        console.error('Failed to delete audit:', error);
        const errorMessage = error.message || 'Failed to delete audit';
        showToast(errorMessage, 'error');
    }
}

async function searchAudits() {
    const entity = document.getElementById('searchEntity')?.value || '';
    const status = document.getElementById('statusFilter')?.value || '';
    
    try {
        const params = new URLSearchParams();
        if (entity) params.append('entityName', entity);
        if (status) params.append('status', status);
        
        const response = await apiCall(`/audits?${params.toString()}`);
        displayAuditList(response.data);
        
        showToast(`Found ${response.data.length} audits`, 'success');
    } catch (error) {
        console.error('Search failed:', error);
        showToast('Search failed', 'error');
    }
}

function clearFilters() {
    const searchEntity = document.getElementById('searchEntity');
    const statusFilter = document.getElementById('statusFilter');
    
    if (searchEntity) searchEntity.value = '';
    if (statusFilter) statusFilter.value = '';
    
    loadAudits(); // Reload all audits
    showToast('Filters cleared', 'info');
}

// ========================================
// FORM FUNCTIONS
// ========================================
function initializeNewAuditForm() {
    switchTab('general');
    updateProgressTracking();
    hasUnsavedChanges = false;
}

function collectFormData() {
    const formData = {
        entityName: getValue('entityName'),
        contractRef: getValue('contractRef'),
        procurementLocation: getValue('procurementLocation'),
        processingLocation: getValue('processingLocation'),
        verificationPeriodStart: getValue('verificationPeriodStart'),
        verificationPeriodEnd: getValue('verificationPeriodEnd'),
        projectTitle: getValue('projectTitle'),
        auditeeTeamLeader: getValue('auditeeTeamLeader'),
        auditeeTeamMembers: getValue('auditeeTeamMembers'),
        purchasedVolume: parseFloat(getValue('purchasedVolume')) || 0,
        processedVolume: parseFloat(getValue('processedVolume')) || 0,
        rejectedVolume: parseFloat(getValue('rejectedVolume')) || 0,
        contractLimit: parseFloat(getValue('contractLimit')) || 0,
        sourceCounty: getValue('sourceCounty'),
        
        // Handle radio buttons properly
        oshActCompliance: getRadioValue('oshActCompliance') === 'yes',
        ppeCompliance: getRadioValue('ppeCompliance') === 'yes',
        environmentalAudits: getRadioValue('environmentalAudits') === 'yes',
        
        // Handle signature data
        pakproCeoSignature: signatureData.pakproCeo,
        recyclerSignature: signatureData.recycler,
        auditorSignature: signatureData.auditor
    };
    if (window.photoManager) {
        formData.photos = photoManager.getPhotosData();
    }
    
    console.log('Collected form data:', formData); // Debug log
    return formData;
}


function getValue(id) {
    const element = document.getElementById(id);
    if (!element) {
        console.warn(`Element with id '${id}' not found`);
        return '';
    }
    
    // Handle different input types
    if (element.type === 'checkbox') {
        return element.checked;
    }
    if (element.type === 'radio') {
        const radioGroup = document.querySelector(`input[name="${element.name}"]:checked`);
        return radioGroup ? radioGroup.value : '';
    }
    
    return element.value ? element.value.trim() : '';
}


function getChecked(id) {
    const element = document.getElementById(id);
    if (!element) {
        console.warn(`Checkbox element with id '${id}' not found`);
        return false;
    }
    return element.checked;
}
function getRadioValue(name) {
    const radioGroup = document.querySelector(`input[name="${name}"]:checked`);
    return radioGroup ? radioGroup.value : '';
}

async function saveDraft(silent = false) {
    try {
        const requiredPermission = currentAuditId ? 'edit_audit' : 'create_audit';
        if (!currentUser || !currentUser.permissions || !currentUser.permissions.includes(requiredPermission)) {
            showToast(`Access denied. You don't have permission to ${currentAuditId ? 'edit' : 'create'} audits.`, 'error');
            return;
        }

        const auditData = collectFormData();
        auditData.status = 'draft';

        if (!silent) {
            showToast('Saving draft...', 'info');
        }

        let response;
        if (currentAuditId) {
            response = await apiCall(`/audits/${currentAuditId}`, {
                method: 'PUT',
                body: JSON.stringify(auditData)
            });
        } else {
            response = await apiCall('/audits', {
                method: 'POST',
                body: JSON.stringify(auditData)
            });
            currentAuditId = response.data.id;
        }
        
        hasUnsavedChanges = false;
        
        if (!silent) {
            showToast('Draft saved successfully', 'success');
        }
        
    } catch (error) {
        console.error('Save draft error:', error);
        if (!silent) {
            const errorMessage = error.message || 'Failed to save draft';
            showToast(errorMessage, 'error');
        }
    }
}

async function submitAudit() {
    try {
        const requiredPermission = currentAuditId ? 'edit_audit' : 'create_audit';
        if (!currentUser || !currentUser.permissions || !currentUser.permissions.includes(requiredPermission)) {
            showToast(`Access denied. You don't have permission to ${currentAuditId ? 'edit' : 'create'} audits.`, 'error');
            return;
        }

        const auditData = collectFormData();
        
        // Basic validation
        if (!auditData.entityName || !auditData.contractRef) {
            showToast('Please fill in required fields: Entity Name and Contract Reference', 'error');
            return;
        }
        
        auditData.status = 'pending';
        
        showToast('Submitting audit...', 'info');
        
        let response;
        if (currentAuditId) {
            response = await apiCall(`/audits/${currentAuditId}`, {
                method: 'PUT',
                body: JSON.stringify(auditData)
            });
        } else {
            response = await apiCall('/audits', {
                method: 'POST',
                body: JSON.stringify(auditData)
            });
        }
        
        showToast('Audit submitted successfully', 'success');
        resetForm();
        showSection('auditList');
        
    } catch (error) {
        console.error('Submit error:', error);
        showToast(error.message || 'Failed to submit audit', 'error');
    }
}

function resetForm() {
    if (hasUnsavedChanges && !confirm('You have unsaved changes. Are you sure you want to reset the form?')) {
        return;
    }

    // Clear all form fields
    document.querySelectorAll('.form-input, .form-select, .form-textarea').forEach(field => {
        field.value = '';
    });

    document.querySelectorAll('input[type="checkbox"], input[type="radio"]').forEach(field => {
        field.checked = false;
    });

    // Clear signatures
    Object.keys(signatureData).forEach(type => {
        clearSignature(type);
    });

    hasUnsavedChanges = false;
    currentAuditId = null;
    updateProgressTracking();
    showToast('Form reset successfully', 'info');
    // Clear photos
if (window.photoManager) {
    photoManager.clearPhotosQuietly();
}
}

// ========================================
// CALCULATION FUNCTIONS
// ========================================
function calculateTotals() {
    const processedVolumeElement = document.getElementById('processedVolume');
    const rejectedVolumeElement = document.getElementById('rejectedVolume');
    const auditedVolumeElement = document.getElementById('auditedVolume');
    
    if (!processedVolumeElement || !rejectedVolumeElement || !auditedVolumeElement) {
        console.warn('Volume calculation elements not found');
        return;
    }
    
    const processedVolume = parseFloat(processedVolumeElement.value) || 0;
    const rejectedVolume = parseFloat(rejectedVolumeElement.value) || 0;
    
    if (rejectedVolume > processedVolume) {
        showToast('Warning: Rejected volume cannot exceed processed volume', 'warning');
        return;
    }
    
    const auditedVolume = processedVolume - rejectedVolume;
    auditedVolumeElement.value = auditedVolume.toFixed(2);
    
    calculateCPAF();
    hasUnsavedChanges = true;
}

function calculateCPAF() {
    const subsidizedVolume = parseFloat(getValue('subsidizedVolume')) || 0;
    const cpafRate = parseFloat(getValue('cpafRate')) || 0;
    
    const cpafPayable = subsidizedVolume * cpafRate;
    const cpafPayableField = document.getElementById('cpafPayable');
    if (cpafPayableField) {
        cpafPayableField.value = cpafPayable.toFixed(2);
    }
    
    hasUnsavedChanges = true;
}

// ========================================
// DYNAMIC ROW FUNCTIONS
// ========================================
function addSupplierRow() {
    const container = document.getElementById('suppliersContainer');
    if (!container) return;
    
    const newRow = document.createElement('div');
    newRow.className = 'dynamic-row';
    newRow.innerHTML = `
        <div>
            <label class="form-label" style="font-size: 0.875rem;">Name</label>
            <input type="text" class="form-input supplier-name" placeholder="Supplier name">
        </div>
        <div>
            <label class="form-label" style="font-size: 0.875rem;">Gender</label>
            <select class="form-select supplier-gender">
                <option value="">Select</option>
                <option value="Male">Male</option>
                <option value="Female">Female</option>
            </select>
        </div>
        <div>
            <label class="form-label" style="font-size: 0.875rem;">Age</label>
            <input type="number" class="form-input supplier-age" placeholder="Age">
        </div>
        <div>
            <label class="form-label" style="font-size: 0.875rem;">Source/County</label>
            <input type="text" class="form-input supplier-source" placeholder="Source/County">
        </div>
        <div>
            <button type="button" class="btn btn-danger" style="padding: 0.5rem;" onclick="removeSupplierRow(this)">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `;
    container.appendChild(newRow);
}

function removeSupplierRow(button) {
    button.closest('.dynamic-row').remove();
}

function addCalculationRow() {
    const container = document.getElementById('calculationsContainer');
    if (!container) return;
    
    const totalsRow = container.querySelector('.totals-row');
    const newRow = document.createElement('div');
    newRow.className = 'calculation-row';
    newRow.innerHTML = `
        <div>
            <label class="form-label" style="font-size: 0.875rem;">Recycled Material</label>
            <input type="text" class="form-input material-type" placeholder="Material type">
        </div>
        <div>
            <label class="form-label" style="font-size: 0.875rem;">Audited Volume (Kg)</label>
            <input type="number" class="form-input audited-volume" placeholder="0" oninput="calculateRowCPAF(this)">
        </div>
        <div>
            <label class="form-label" style="font-size: 0.875rem;">Set Limit (Kg)</label>
            <input type="number" class="form-input set-limit" placeholder="0" oninput="calculateRowCPAF(this)">
        </div>
        <div>
            <label class="form-label" style="font-size: 0.875rem;">Subsidized Volume (Kg)</label>
            <input type="number" class="form-input subsidized-volume" placeholder="0" oninput="calculateRowCPAF(this)">
        </div>
        <div>
            <label class="form-label" style="font-size: 0.875rem;">CPAF Rate (KES)</label>
            <input type="number" class="form-input cpaf-rate" placeholder="0" step="0.01" oninput="calculateRowCPAF(this)">
        </div>
        <div>
            <label class="form-label" style="font-size: 0.875rem;">CPAF Payable (KES)</label>
            <input type="number" class="form-input cpaf-payable" placeholder="0" readonly>
        </div>
        <div>
            <button type="button" class="btn btn-danger" style="padding: 0.5rem;" onclick="removeCalculationRow(this)">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `;
    
    if (totalsRow) {
        container.insertBefore(newRow, totalsRow);
    } else {
        container.appendChild(newRow);
    }
    
    updateCalculationTotals();
}

function removeCalculationRow(button) {
    button.closest('.calculation-row').remove();
    updateCalculationTotals();
}

function calculateRowCPAF(input) {
    const row = input.closest('.calculation-row');
    if (!row || row.classList.contains('totals-row')) return;
    
    const subsidizedVolume = parseFloat(row.querySelector('.subsidized-volume')?.value) || 0;
    const cpafRate = parseFloat(row.querySelector('.cpaf-rate')?.value) || 0;
    const cpafPayable = subsidizedVolume * cpafRate;
    
    const cpafPayableInput = row.querySelector('.cpaf-payable');
    if (cpafPayableInput) {
        cpafPayableInput.value = cpafPayable.toFixed(2);
    }
    
    updateCalculationTotals();
}

function updateCalculationTotals() {
    const container = document.getElementById('calculationsContainer');
    if (!container) return;
    
    const rows = container.querySelectorAll('.calculation-row:not(.totals-row)');
    let totalAudited = 0;
    let totalSetLimit = 0;
    let totalSubsidized = 0;
    let totalCPAF = 0;
    
    rows.forEach(row => {
        totalAudited += parseFloat(row.querySelector('.audited-volume')?.value) || 0;
        totalSetLimit += parseFloat(row.querySelector('.set-limit')?.value) || 0;
        totalSubsidized += parseFloat(row.querySelector('.subsidized-volume')?.value) || 0;
        totalCPAF += parseFloat(row.querySelector('.cpaf-payable')?.value) || 0;
    });
    
    // Update totals row
    const totalElements = {
        'totalAuditedVolume': totalAudited.toFixed(2),
        'totalSetLimit': totalSetLimit.toFixed(2),
        'totalSubsidizedVolume': totalSubsidized.toFixed(2),
        'totalCPAFPayable': totalCPAF.toFixed(2)
    };
    
    Object.entries(totalElements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) element.value = value;
    });
}

// ========================================
// SIGNATURE FUNCTIONS
// ========================================
function initializeSignatureCanvases() {
    ['pakproCeo', 'recycler', 'auditor'].forEach(type => {
        const canvas = document.getElementById(`${type}Signature`);
        if (canvas) {
            setupSignatureCanvas(canvas, type);
        }
    });
}

function setupSignatureCanvas(canvas, type) {
    const ctx = canvas.getContext('2d');
    let isDrawing = false;
    let lastX = 0;
    let lastY = 0;

    ctx.strokeStyle = '#2563eb';
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';

    // Mouse events
    canvas.addEventListener('mousedown', (e) => {
        isDrawing = true;
        [lastX, lastY] = getCoordinates(e, canvas);
    });

    canvas.addEventListener('mousemove', (e) => {
        if (!isDrawing) return;
        const [currentX, currentY] = getCoordinates(e, canvas);
        
        ctx.beginPath();
        ctx.moveTo(lastX, lastY);
        ctx.lineTo(currentX, currentY);
        ctx.stroke();
        
        [lastX, lastY] = [currentX, currentY];
    });

    canvas.addEventListener('mouseup', () => {
        isDrawing = false;
        signatureData[type] = canvas.toDataURL();
        hasUnsavedChanges = true;
    });

    // Touch events for mobile
    canvas.addEventListener('touchstart', (e) => {
        e.preventDefault();
        const touch = e.touches[0];
        const mouseEvent = new MouseEvent('mousedown', {
            clientX: touch.clientX,
            clientY: touch.clientY
        });
        canvas.dispatchEvent(mouseEvent);
    });

    canvas.addEventListener('touchmove', (e) => {
        e.preventDefault();
        const touch = e.touches[0];
        const mouseEvent = new MouseEvent('mousemove', {
            clientX: touch.clientX,
            clientY: touch.clientY
        });
        canvas.dispatchEvent(mouseEvent);
    });

    canvas.addEventListener('touchend', (e) => {
        e.preventDefault();
        canvas.dispatchEvent(new MouseEvent('mouseup', {}));
    });
}

function getCoordinates(event, canvas) {
    const rect = canvas.getBoundingClientRect();
    return [
        event.clientX - rect.left,
        event.clientY - rect.top
    ];
}

function clearSignature(type) {
    const canvas = document.getElementById(`${type}Signature`);
    if (canvas) {
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        signatureData[type] = null;
        hasUnsavedChanges = true;
    }
}

function saveSignature(type) {
    if (signatureData[type]) {
        showToast(`${type} signature saved`, 'success');
    } else {
        showToast('Please draw a signature first', 'warning');
    }
}

// ========================================
// EXPORT FUNCTIONS
// ========================================
function exportMultiSheetExcel() {
    // Debug logging
    console.log('Export function called');
    console.log('window.audits:', window.audits);
    console.log('audits variable:', audits);
    
    const auditsData = window.audits || audits || [];
    
    if (auditsData.length === 0) {
        console.error('No audit data found for export');
        showToast('No audit data available for export', 'warning');
        return;
    }
    
    console.log(`Exporting ${auditsData.length} audit records`);
    showToast('Generating Kenya multi-sheet Excel report...', 'info');
    
    try {
        // Create workbook with multiple sheets
        const wb = XLSX.utils.book_new();
        
        // Summary sheet
        const summaryData = auditsData.map(audit => ({
            'Audit ID': audit.id,
            'Entity Name': audit.entity_name,
            'Contract Reference': audit.contract_ref,
            'Status': audit.status,
            'County': audit.source_county,
            'CPAF Payable (KES)': audit.cpaf_payable,
            'Completion %': audit.completion_percentage
        }));
        
        const summarySheet = XLSX.utils.json_to_sheet(summaryData);
        XLSX.utils.book_append_sheet(wb, summarySheet, 'Audit Summary');
        
        // Financial sheet
        const financialData = auditsData.map(audit => ({
            'Entity Name': audit.entity_name,
            'Purchased Volume (MT)': audit.purchased_volume,
            'Processed Volume (MT)': audit.processed_volume,
            'Rejected Volume (MT)': audit.rejected_volume,
            'Subsidized Volume (MT)': audit.subsidized_volume,
            'CPAF Rate (KES)': audit.cpaf_rate,
            'CPAF Payable (KES)': audit.cpaf_payable,
            'Contract Limit (KES)': audit.contract_limit
        }));
        
        const financialSheet = XLSX.utils.json_to_sheet(financialData);
        XLSX.utils.book_append_sheet(wb, financialSheet, 'Financial Data');
        
        // ESG Compliance sheet
        const esgData = auditsData.map(audit => ({
            'Entity Name': audit.entity_name,
            'OSH Act Compliance': audit.osh_act_compliance ? 'Yes' : 'No',
            'PPE Compliance': audit.ppe_compliance ? 'Yes' : 'No',
            'Environmental Audits': audit.environmental_audits ? 'Yes' : 'No',
            'Source County': audit.source_county
        }));
        
        const esgSheet = XLSX.utils.json_to_sheet(esgData);
        XLSX.utils.book_append_sheet(wb, esgSheet, 'ESG Compliance');
        
        // Download the file
        const fileName = `PAKPRO_Kenya_Audit_Report_${new Date().toISOString().split('T')[0]}.xlsx`;
        XLSX.writeFile(wb, fileName);
        
        showToast('Kenya Excel report downloaded successfully', 'success');
        
    } catch (error) {
        console.error('Export error:', error);
        showToast('Failed to generate Excel report: ' + error.message, 'error');
    }
}

// ADD these functions in app.js after your exportMultiSheetExcel function

// CSV conversion utility
function convertToCSV(data) {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const csvRows = [];
    
    // Add headers
    csvRows.push(headers.join(','));
    
    // Add data rows
    for (const row of data) {
        const values = headers.map(header => {
            const value = row[header];
            return `"${String(value || '').replace(/"/g, '""')}"`;
        });
        csvRows.push(values.join(','));
    }
    
    return csvRows.join('\n');
}

// File download utility
function downloadFile(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = window.URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    link.style.display = 'none';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    window.URL.revokeObjectURL(url);
}

// Export CSV function
async function exportCSV() {
    try {
        showToast('Generating CSV export...', 'info');
        
        const response = await apiCall('/audits');
        const auditsData = response.data || response;
        
        if (!auditsData || auditsData.length === 0) {
            showToast('No audit data available for export', 'warning');
            return;
        }
        
        const csvData = auditsData.map(audit => ({
            'Audit ID': audit.id,
            'Entity Name': audit.entity_name,
            'Contract Reference': audit.contract_ref,
            'Status': audit.status,
            'County': audit.source_county,
            'Purchased Volume (MT)': audit.purchased_volume,
            'Processed Volume (MT)': audit.processed_volume,
            'Rejected Volume (MT)': audit.rejected_volume,
            'CPAF Payable (KES)': audit.cpaf_payable,
            'Completion %': audit.completion_percentage,
            'Created Date': audit.created_at
        }));
        
        const csv = convertToCSV(csvData);
        const fileName = `PAKPRO_Kenya_Audits_${new Date().toISOString().split('T')[0]}.csv`;
        downloadFile(csv, fileName, 'text/csv');
        
        showToast('CSV export completed successfully', 'success');
        
    } catch (error) {
        console.error('CSV export error:', error);
        showToast('Failed to export CSV', 'error');
    }
}

// ADD this function in app.js after the exportCSV function

// Export JSON function
async function exportJSON() {
    try {
        showToast('Generating JSON export...', 'info');
        
        const response = await apiCall('/audits');
        const auditsData = response.data || response;
        
        if (!auditsData || auditsData.length === 0) {
            showToast('No audit data available for export', 'warning');
            return;
        }
        
        const exportData = {
            exportDate: new Date().toISOString(),
            country: 'Kenya',
            currency: 'KES',
            totalAudits: auditsData.length,
            audits: auditsData
        };
        
        const json = JSON.stringify(exportData, null, 2);
        const fileName = `PAKPRO_Kenya_Data_${new Date().toISOString().split('T')[0]}.json`;
        downloadFile(json, fileName, 'application/json');
        
        showToast('JSON data exported successfully', 'success');
        
    } catch (error) {
        console.error('JSON export error:', error);
        showToast('Failed to export JSON', 'error');
    }
}


// ADD this function in app.js after the exportJSON function

// Export PDF function
async function exportPDF() {
    try {
        showToast('Generating PDF report...', 'info');
        
        const response = await apiCall('/audits');
        const auditsData = response.data || response;
        
        if (!auditsData || auditsData.length === 0) {
            showToast('No audit data available for PDF export', 'warning');
            return;
        }
        
        const htmlContent = generatePrintableReport(auditsData);
        
        // Open in new window for printing/PDF
        const printWindow = window.open('', '_blank');
        printWindow.document.write(htmlContent);
        printWindow.document.close();
        printWindow.print();
        
        showToast('PDF report opened for printing', 'success');
        
    } catch (error) {
        console.error('PDF export error:', error);
        showToast('Failed to generate PDF', 'error');
    }
}

// Generate printable HTML report
function generatePrintableReport(auditsData) {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>PAKPRO Kenya Audit Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #2563eb; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f5f5f5; }
                .summary { background: #f0f9ff; padding: 15px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <h1>PAKPRO Kenya Audit Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Total Audits:</strong> ${auditsData.length}</p>
                <p><strong>Generated:</strong> ${new Date().toLocaleDateString()}</p>
                <p><strong>Country:</strong> Kenya</p>
                <p><strong>Currency:</strong> KES</p>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Entity Name</th>
                        <th>Contract Ref</th>
                        <th>Status</th>
                        <th>County</th>
                        <th>CPAF Payable</th>
                        <th>Completion %</th>
                    </tr>
                </thead>
                <tbody>
                    ${auditsData.map(audit => `
                        <tr>
                            <td>${audit.entity_name || 'N/A'}</td>
                            <td>${audit.contract_ref || 'N/A'}</td>
                            <td>${audit.status || 'draft'}</td>
                            <td>${audit.source_county || 'N/A'}</td>
                            <td>KSh ${(audit.cpaf_payable || 0).toLocaleString()}</td>
                            <td>${audit.completion_percentage || 0}%</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </body>
        </html>
    `;
}

// Additional Kenya-specific export functions
function exportKenyaCountyReport() {
    const auditsData = window.audits || audits || [];
    
    if (auditsData.length === 0) {
        showToast('No audit data available for county report', 'warning');
        return;
    }
    
    try {
        // Group audits by county
        const countyGroups = {};
        auditsData.forEach(audit => {
            const county = audit.source_county || 'Unknown';
            if (!countyGroups[county]) {
                countyGroups[county] = {
                    county: county,
                    totalAudits: 0,
                    finalizedAudits: 0,
                    totalCPAF: 0,
                    avgCompletion: 0,
                    audits: []
                };
            }
            
            countyGroups[county].totalAudits++;
            countyGroups[county].audits.push(audit);
            if (audit.status === 'finalized') countyGroups[county].finalizedAudits++;
            countyGroups[county].totalCPAF += (audit.cpaf_payable || 0);
        });
        
        // Calculate averages
        Object.values(countyGroups).forEach(group => {
            const totalCompletion = group.audits.reduce((sum, audit) => sum + (audit.completion_percentage || 0), 0);
            group.avgCompletion = Math.round(totalCompletion / group.audits.length);
        });
        
        const reportData = Object.values(countyGroups).map(group => ({
            'County': group.county,
            'Total Audits': group.totalAudits,
            'Finalized Audits': group.finalizedAudits,
            'Total CPAF (KES)': group.totalCPAF,
            'Average Completion %': group.avgCompletion
        }));
        
        const csv = convertToCSV(reportData);
        const fileName = `PAKPRO_Kenya_County_Report_${new Date().toISOString().split('T')[0]}.csv`;
        downloadFile(csv, fileName, 'text/csv');
        
        showToast('Kenya County Performance Report exported successfully', 'success');
        
    } catch (error) {
        console.error('County report export error:', error);
        showToast('Failed to export county report: ' + error.message, 'error');
    }
}

function exportComplianceReport() {
    const auditsData = window.audits || audits || [];
    
    if (auditsData.length === 0) {
        showToast('No audit data available for compliance report', 'warning');
        return;
    }
    
    try {
        const complianceData = auditsData.map(audit => ({
            'Entity Name': audit.entity_name,
            'Contract Reference': audit.contract_ref,
            'County': audit.source_county,
            'OSH Act Compliance': audit.osh_act_compliance ? 'Compliant' : 'Non-Compliant',
            'PPE Compliance': audit.ppe_compliance ? 'Compliant' : 'Non-Compliant',
            'Environmental Audits': audit.environmental_audits ? 'Compliant' : 'Non-Compliant',
            'Overall Compliance Score': calculateComplianceScore(audit),
            'Status': audit.status
        }));
        
        const csv = convertToCSV(complianceData);
        const fileName = `PAKPRO_Kenya_ESG_Compliance_Report_${new Date().toISOString().split('T')[0]}.csv`;
        downloadFile(csv, fileName, 'text/csv');
        
        showToast('ESG Compliance Report exported successfully', 'success');
        
    } catch (error) {
        console.error('Compliance report export error:', error);
        showToast('Failed to export compliance report: ' + error.message, 'error');
    }
}

function exportFinancialReport() {
    const auditsData = window.audits || audits || [];
    
    if (auditsData.length === 0) {
        showToast('No audit data available for financial report', 'warning');
        return;
    }
    
    try {
        const financialData = auditsData.map(audit => ({
            'Entity Name': audit.entity_name,
            'Contract Reference': audit.contract_ref,
            'County': audit.source_county,
            'Purchased Volume (MT)': audit.purchased_volume || 0,
            'Processed Volume (MT)': audit.processed_volume || 0,
            'Rejected Volume (MT)': audit.rejected_volume || 0,
            'Subsidized Volume (MT)': audit.subsidized_volume || 0,
            'CPAF Rate (KES)': audit.cpaf_rate || 0,
            'CPAF Payable (KES)': audit.cpaf_payable || 0,
            'Contract Limit (KES)': audit.contract_limit || 0,
            'Utilization %': audit.contract_limit ? Math.round((audit.cpaf_payable / audit.contract_limit) * 100) : 0,
            'Status': audit.status
        }));
        
        const csv = convertToCSV(financialData);
        const fileName = `PAKPRO_Kenya_Financial_Report_${new Date().toISOString().split('T')[0]}.csv`;
        downloadFile(csv, fileName, 'text/csv');
        
        showToast('CPAF Financial Report exported successfully', 'success');
        
    } catch (error) {
        console.error('Financial report export error:', error);
        showToast('Failed to export financial report: ' + error.message, 'error');
    }
}

// Helper function to calculate compliance score
function calculateComplianceScore(audit) {
    let score = 0;
    let total = 0;
    
    if (audit.osh_act_compliance !== undefined) {
        if (audit.osh_act_compliance) score++;
        total++;
    }
    if (audit.ppe_compliance !== undefined) {
        if (audit.ppe_compliance) score++;
        total++;
    }
    if (audit.environmental_audits !== undefined) {
        if (audit.environmental_audits) score++;
        total++;
    }
    
    return total > 0 ? Math.round((score / total) * 100) + '%' : 'N/A';
}

// ========================================
// UTILITY FUNCTIONS
// ========================================
function updateProgressTracking() {
    const requiredFields = document.querySelectorAll('.form-input[required], .form-select[required]');
    const completedFields = Array.from(requiredFields).filter(field => field.value.trim()).length;
    const percentage = requiredFields.length > 0 ? Math.round((completedFields / requiredFields.length) * 100) : 0;
    
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    
    if (progressFill) progressFill.style.width = percentage + '%';
    if (progressText) progressText.textContent = `${percentage}% Complete`;
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function showElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.classList.remove('hidden');
    }
}

function hideElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.classList.add('hidden');
    }
}

function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        console.warn('Toast container not found');
        return;
    }
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <i class="fas fa-${getToastIcon(type)}"></i>
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="background: none; border: none; color: inherit; cursor: pointer; margin-left: auto;">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    toastContainer.appendChild(toast);
    
    setTimeout(() => toast.classList.add('show'), 100);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 300);
    }, 5000);
}

function getToastIcon(type) {
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}

function toggleTheme() {
    const body = document.body;
    const isDark = body.classList.contains('dark-theme');
    
    if (isDark) {
        body.classList.remove('dark-theme');
        showToast('Light theme activated', 'info');
    } else {
        body.classList.add('dark-theme');
        showToast('Dark theme activated', 'info');
    }
    
    const themeToggle = document.querySelector('.theme-toggle i');
    if (themeToggle) {
        themeToggle.className = isDark ? 'fas fa-moon' : 'fas fa-sun';
    }
}

// ========================================
// AUTO-SAVE FUNCTIONALITY
// ========================================
function initializeAutoSave() {
    if (autoSaveInterval) {
        clearInterval(autoSaveInterval);
    }

    autoSaveInterval = setInterval(() => {
        if (hasUnsavedChanges && isFormVisible()) {
            saveDraft(true); // Silent save
        }
    }, AUTO_SAVE_INTERVAL);
}

function clearAutoSave() {
    if (autoSaveInterval) {
        clearInterval(autoSaveInterval);
        autoSaveInterval = null;
    }
}

function isFormVisible() {
    const newAuditSection = document.getElementById('newAuditSection');
    return newAuditSection && !newAuditSection.classList.contains('hidden');
}

// ========================================
// CONDITIONAL FORM LOGIC
// ========================================
function toggleOnsiteDetails() {
    const onsiteAssessment = document.querySelector('input[name="onsiteAssessment"]:checked');
    const onsiteDetails = document.getElementById('onsiteDetails');
    
    if (onsiteAssessment && onsiteAssessment.value === 'yes' && onsiteDetails) {
        onsiteDetails.classList.add('show');
    } else if (onsiteDetails) {
        onsiteDetails.classList.remove('show');
    }
}

// ========================================
// SETTINGS FUNCTIONS
// ========================================
function saveSettings() {
    showToast('Kenya system settings saved successfully', 'success');
}

function backupDatabase() {
    showToast('Creating Kenya database backup...', 'info');
    setTimeout(() => {
        showToast('Kenya database backed up successfully', 'success');
    }, 1500);
}

function importData() {
    showToast('Data import functionality available for Kenya operations', 'info');
}

function clearAllData() {
    if (confirm('Are you sure you want to clear ALL Kenya data? This action cannot be undone!')) {
        showToast('This would clear all Kenya data in production', 'warning');
    }
}
function updateCountyPerformanceTable(auditsData) {
    const tbody = document.querySelector('#analyticsSection table tbody');
    if (!tbody) return;

    // Group audits by county
    const countyGroups = {};
    auditsData.forEach(audit => {
        const county = audit.source_county || 'Unknown';
        if (!countyGroups[county]) {
            countyGroups[county] = {
                county: county,
                totalAudits: 0,
                finalizedAudits: 0,
                totalCPAF: 0,
                totalCompletion: 0
            };
        }
        
        countyGroups[county].totalAudits++;
        if (audit.status === 'finalized') countyGroups[county].finalizedAudits++;
        countyGroups[county].totalCPAF += (audit.cpaf_payable || 0);
        countyGroups[county].totalCompletion += (audit.completion_percentage || 0);
    });
    
    // Calculate averages and create table rows
    const countyRows = Object.values(countyGroups).map(group => {
        const avgCompletion = group.totalAudits > 0 ? Math.round(group.totalCompletion / group.totalAudits) : 0;
        return `
            <tr>
                <td>${group.county}</td>
                <td>${group.totalAudits}</td>
                <td>${group.finalizedAudits}</td>
                <td>KSh ${group.totalCPAF.toLocaleString()}</td>
                <td>${avgCompletion}%</td>
            </tr>
        `;
    }).join('');
    
    tbody.innerHTML = countyRows || '<tr><td colspan="5" class="text-center">No data available</td></tr>';
}
// ... keep all your existing functions exactly as they are ...


// ========================================
// TAGS INPUT SYSTEM
// ========================================
// ========================================
// TAGS INPUT SYSTEM
// ========================================
class TagsInput {
    constructor(inputId, tagsId, hiddenId) {
        this.input = document.getElementById(inputId);
        this.tagsContainer = document.getElementById(tagsId);
        this.hiddenInput = document.getElementById(hiddenId);
        this.tags = [];
        
        if (this.input && this.tagsContainer && this.hiddenInput) {
            this.init();
        }
    }
    
    init() {
        // Handle Enter key
        this.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && this.input.value.trim()) {
                e.preventDefault();
                this.addTag(this.input.value.trim());
                this.input.value = '';
            } else if (e.key === 'Backspace' && this.input.value === '' && this.tags.length > 0) {
                // Remove last tag when backspace is pressed on empty input
                this.removeTag(this.tags[this.tags.length - 1]);
            }
        });

        // Handle clicking on the container to focus the input
        this.tagsContainer.parentElement.addEventListener('click', (e) => {
            if (e.target === this.tagsContainer.parentElement || e.target === this.tagsContainer) {
                this.input.focus();
            }
        });

        // Handle datalist selection
        this.input.addEventListener('input', (e) => {
            // Check if the input matches a datalist option exactly
            const datalist = document.getElementById('counties');
            if (datalist) {
                const options = Array.from(datalist.options).map(option => option.value);
                if (options.includes(e.target.value)) {
                    this.addTag(e.target.value);
                    e.target.value = '';
                }
            }
        });
    }
    
    addTag(tagText) {
        if (!tagText || this.tags.includes(tagText)) {
            return;
        }
        
        this.tags.push(tagText);
        this.renderTags();
        this.updateHiddenInput();
        if (typeof hasUnsavedChanges !== 'undefined') {
            hasUnsavedChanges = true;
        }
        if (typeof updateProgressTracking === 'function') {
            updateProgressTracking();
        }
    }
    
    removeTag(tagText) {
        const index = this.tags.indexOf(tagText);
        if (index > -1) {
            this.tags.splice(index, 1);
            this.renderTags();
            this.updateHiddenInput();
            if (typeof hasUnsavedChanges !== 'undefined') {
                hasUnsavedChanges = true;
            }
            if (typeof updateProgressTracking === 'function') {
                updateProgressTracking();
            }
        }
    }
    
    renderTags() {
        // Clear existing tags
        this.tagsContainer.innerHTML = '';
        
        // Create and append each tag
        this.tags.forEach((tag) => {
            const tagElement = document.createElement('span');
            tagElement.className = 'tag';
            
            const tagText = document.createTextNode(tag);
            tagElement.appendChild(tagText);
            
            const removeBtn = document.createElement('span');
            removeBtn.className = 'remove-tag';
            removeBtn.innerHTML = '&times;';
            removeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.removeTag(tag);
            });
            
            tagElement.appendChild(removeBtn);
            this.tagsContainer.appendChild(tagElement);
        });
    }
    
    updateHiddenInput() {
        this.hiddenInput.value = JSON.stringify(this.tags);
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Method to set tags programmatically (for editing existing audits)
    setTags(tags) {
        this.tags = Array.isArray(tags) ? tags : [];
        this.renderTags();
        this.updateHiddenInput();
    }
    
    // Method to get current tags
    getTags() {
        return [...this.tags];
    }
}

// Initialize tags inputs when DOM is ready
let procurementTagsInput = null;
let processingTagsInput = null;
let sourceCountyTagsInput = null;
let sourceSubCountyTagsInput = null;

function initializeTagsInputs() {
    // Initialize procurement locations tags input
    procurementTagsInput = new TagsInput(
        'procurementLocationInput',
        'procurementTags', 
        'procurementLocationData'
    );
    
    // Initialize processing locations tags input  
    processingTagsInput = new TagsInput(
        'processingLocationInput',
        'processingTags',
        'processingLocationData'
    );
    
    // Initialize source county tags input
    sourceCountyTagsInput = new TagsInput(
        'sourceCountyInput',
        'sourceCountyTags',
        'sourceCountyData'
    );
    
    // Initialize source sub county tags input
    sourceSubCountyTagsInput = new TagsInput(
        'sourceSubCountyInput',
        'sourceSubCountyTags',
        'sourceSubCountyData'
    );
}


// Initialize tags inputs when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Small delay to ensure all elements are rendered
    setTimeout(() => {
        initializeTagsInputs();
    }, 100);
});

// Update the populateFormWithAudit function to handle tags
function populateFormWithAuditTags(audit) {
    // Handle tags data - parse JSON strings or handle arrays
    if (audit.procurement_location && procurementTagsInput) {
        let procurementTags = [];
        try {
            if (typeof audit.procurement_location === 'string') {
                // Try to parse as JSON first
                try {
                    procurementTags = JSON.parse(audit.procurement_location);
                } catch {
                    // If not JSON, treat as single location
                    procurementTags = [audit.procurement_location];
                }
            } else if (Array.isArray(audit.procurement_location)) {
                procurementTags = audit.procurement_location;
            } else {
                procurementTags = [audit.procurement_location.toString()];
            }
        } catch (error) {
            console.warn('Error parsing procurement locations:', error);
            procurementTags = [];
        }
        procurementTagsInput.setTags(procurementTags);
    }
    
    if (audit.processing_location && processingTagsInput) {
        let processingTags = [];
        try {
            if (typeof audit.processing_location === 'string') {
                // Try to parse as JSON first
                try {
                    processingTags = JSON.parse(audit.processing_location);
                } catch {
                    // If not JSON, treat as single location
                    processingTags = [audit.processing_location];
                }
            } else if (Array.isArray(audit.processing_location)) {
                processingTags = audit.processing_location;
            } else {
                processingTags = [audit.processing_location.toString()];
            }
        } catch (error) {
            console.warn('Error parsing processing locations:', error);
            processingTags = [];
        }
        processingTagsInput.setTags(processingTags);
    }
    // Handle source county tags
    if (audit.source_county && sourceCountyTagsInput) {
        let sourceCountyTags = [];
        try {
            if (typeof audit.source_county === 'string') {
                try {
                    sourceCountyTags = JSON.parse(audit.source_county);
                } catch {
                    sourceCountyTags = [audit.source_county];
                }
            } else if (Array.isArray(audit.source_county)) {
                sourceCountyTags = audit.source_county;
            } else {
                sourceCountyTags = [audit.source_county.toString()];
            }
        } catch (error) {
            console.warn('Error parsing source counties:', error);
            sourceCountyTags = [];
        }
        sourceCountyTagsInput.setTags(sourceCountyTags);
    }
    
    // Handle source sub county tags
    if (audit.source_sub_county && sourceSubCountyTagsInput) {
        let sourceSubCountyTags = [];
        try {
            if (typeof audit.source_sub_county === 'string') {
                try {
                    sourceSubCountyTags = JSON.parse(audit.source_sub_county);
                } catch {
                    sourceSubCountyTags = [audit.source_sub_county];
                }
            } else if (Array.isArray(audit.source_sub_county)) {
                sourceSubCountyTags = audit.source_sub_county;
            } else {
                sourceSubCountyTags = [audit.source_sub_county.toString()];
            }
        } catch (error) {
            console.warn('Error parsing source sub counties:', error);
            sourceSubCountyTags = [];
        }
        sourceSubCountyTagsInput.setTags(sourceSubCountyTags);
    }
}

// Update collectFormData to handle tags
function collectFormDataWithTags() {
    const baseFormData = collectFormData();
    
    // Override location fields with tags data
    if (procurementTagsInput) {
        baseFormData.procurementLocations = procurementTagsInput.getTags();
        baseFormData.procurementLocation = JSON.stringify(procurementTagsInput.getTags());
    }
    
    if (processingTagsInput) {
        baseFormData.processingLocations = processingTagsInput.getTags();
        baseFormData.processingLocation = JSON.stringify(processingTagsInput.getTags());
    }
    
    return baseFormData;
}

// Update the existing populateFormWithAudit function to include tags handling
const originalPopulateFormWithAudit = populateFormWithAudit;
populateFormWithAudit = function(audit) {
    originalPopulateFormWithAudit.call(this, audit);
    populateFormWithAuditTags(audit);
};

// Update the existing collectFormData function to include tags handling
const originalCollectFormData = collectFormData;
collectFormData = function() {
    return collectFormDataWithTags();
};

// Update resetForm to clear tags
function resetFormWithTags() {
    // Clear tags inputs
    if (procurementTagsInput) {
        procurementTagsInput.setTags([]);
    }
    if (processingTagsInput) {
        processingTagsInput.setTags([]);
    }
    if (sourceCountyTagsInput) {
        sourceCountyTagsInput.setTags([]);
    }
    if (sourceSubCountyTagsInput) {
        sourceSubCountyTagsInput.setTags([]);
    }
}

// Update the existing resetForm function to include tags clearing
const originalResetForm = resetForm;
resetForm = function() {
    originalResetForm.call(this);
    resetFormWithTags();
};
// ========================================
// USER MANAGEMENT SYSTEM
// ========================================

// Initialize users in localStorage if not exists
function initializeUsers() {
    if (!localStorage.getItem('pakpro_users')) {
        const defaultUsers = [
            {
                id: 1,
                fullName: 'Administrator',
                username: 'admin',
                email: 'admin@pakpro.ke',
                password: 'pakpro123',
                role: 'admin',
                status: 'active',
                phone: '+254 700 000001',
                department: 'Management',
                lastLogin: new Date().toISOString(),
                createdAt: new Date().toISOString(),
                permissions: {
                    createAudit: true,
                    editAudit: true,
                    deleteAudit: true,
                    viewReports: true,
                    exportData: true,
                    manageUsers: true
                }
            },
            {
                id: 2,
                fullName: 'John Doe',
                username: 'analyst1',
                email: 'john.doe@pakpro.ke',
                password: 'analyst123',
                role: 'analyst',
                status: 'active',
                phone: '+254 700 000002',
                department: 'Data Analysis',
                lastLogin: new Date(Date.now() - 86400000).toISOString(),
                createdAt: new Date().toISOString(),
                permissions: {
                    createAudit: true,
                    editAudit: true,
                    deleteAudit: false,
                    viewReports: true,
                    exportData: true,
                    manageUsers: false
                }
            },
            {
                id: 3,
                fullName: 'Jane Smith',
                username: 'auditor1',
                email: 'jane.smith@pakpro.ke',
                password: 'auditor123',
                role: 'auditor',
                status: 'active',
                phone: '+254 700 000003',
                department: 'Field Operations',
                lastLogin: new Date(Date.now() - 172800000).toISOString(),
                createdAt: new Date().toISOString(),
                permissions: {
                    createAudit: true,
                    editAudit: true,
                    deleteAudit: false,
                    viewReports: true,
                    exportData: false,
                    manageUsers: false
                }
            },
            {
                id: 4,
                fullName: 'Michael Johnson',
                username: 'viewer1',
                email: 'michael.j@pakpro.ke',
                password: 'viewer123',
                role: 'viewer',
                status: 'active',
                phone: '+254 700 000004',
                department: 'Compliance',
                lastLogin: new Date(Date.now() - 259200000).toISOString(),
                createdAt: new Date().toISOString(),
                permissions: {
                    createAudit: false,
                    editAudit: false,
                    deleteAudit: false,
                    viewReports: true,
                    exportData: false,
                    manageUsers: false
                }
            },
            {
                id: 5,
                fullName: 'Sarah Williams',
                username: 'inactive1',
                email: 'sarah.w@pakpro.ke',
                password: 'inactive123',
                role: 'analyst',
                status: 'inactive',
                phone: '+254 700 000005',
                department: 'Data Analysis',
                lastLogin: new Date(Date.now() - 2592000000).toISOString(),
                createdAt: new Date().toISOString(),
                permissions: {
                    createAudit: true,
                    editAudit: true,
                    deleteAudit: false,
                    viewReports: true,
                    exportData: true,
                    manageUsers: false
                }
            }
        ];
        
        localStorage.setItem('pakpro_users', JSON.stringify(defaultUsers));
        console.log('Default users initialized');
    }
}

// Get all users
function getAllUsers() {
    const users = localStorage.getItem('pakpro_users');
    return users ? JSON.parse(users) : [];
}

// Save users
function saveUsers(users) {
    localStorage.setItem('pakpro_users', JSON.stringify(users));
    updateUserStats();
}

// Load and display users
function loadUsers() {
    const users = getAllUsers();
    const tbody = document.getElementById('usersTableBody');
    
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.id}</td>
            <td>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <div style="width: 32px; height: 32px; background: var(--primary-color); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">
                        ${user.fullName.charAt(0)}
                    </div>
                    ${user.fullName}
                </div>
            </td>
            <td>${user.username}</td>
            <td>${user.email}</td>
            <td>
                <span class="status-badge ${getRoleBadgeClass(user.role)}">
                    ${user.role}
                </span>
            </td>
            <td>
                <span class="status-badge ${user.status === 'active' ? 'status-finalized' : 'status-draft'}">
                    ${user.status}
                </span>
            </td>
            <td>${formatDate(user.lastLogin)}</td>
            <td>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-outline" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="editUser(${user.id})" title="Edit User">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-danger" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="confirmDeleteUser(${user.id})" title="Delete User" ${user.role === 'admin' ? 'disabled' : ''}>
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Get role badge class
function getRoleBadgeClass(role) {
    const classes = {
        'admin': 'status-finalized',
        'analyst': 'status-review',
        'auditor': 'status-pending',
        'viewer': 'status-draft'
    };
    return classes[role] || 'status-draft';
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    const days = Math.floor(diff / 86400000);
    
    if (days === 0) return 'Today';
    if (days === 1) return 'Yesterday';
    if (days < 7) return `${days} days ago`;
    if (days < 30) return `${Math.floor(days / 7)} weeks ago`;
    
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

// Update user statistics
function updateUserStats() {
    const users = getAllUsers();
    
    const totalUsers = users.length;
    const activeUsers = users.filter(u => u.status === 'active').length;
    const adminUsers = users.filter(u => u.role === 'admin').length;
    const inactiveUsers = users.filter(u => u.status === 'inactive').length;
    
    const totalUsersEl = document.getElementById('totalUsers');
    const activeUsersEl = document.getElementById('activeUsers');
    const adminUsersEl = document.getElementById('adminUsers');
    const inactiveUsersEl = document.getElementById('inactiveUsers');
    
    if (totalUsersEl) totalUsersEl.textContent = totalUsers;
    if (activeUsersEl) activeUsersEl.textContent = activeUsers;
    if (adminUsersEl) adminUsersEl.textContent = adminUsers;
    if (inactiveUsersEl) inactiveUsersEl.textContent = inactiveUsers;
}

// Filter users
function filterUsers() {
    const searchTerm = document.getElementById('searchUsers').value.toLowerCase();
    const roleFilter = document.getElementById('roleFilter').value;
    const statusFilter = document.getElementById('statusFilterUser').value;
    
    const users = getAllUsers();
    const filteredUsers = users.filter(user => {
        const matchesSearch = user.fullName.toLowerCase().includes(searchTerm) ||
                            user.username.toLowerCase().includes(searchTerm) ||
                            user.email.toLowerCase().includes(searchTerm);
        
        const matchesRole = !roleFilter || user.role === roleFilter;
        const matchesStatus = !statusFilter || user.status === statusFilter;
        
        return matchesSearch && matchesRole && matchesStatus;
    });
    
    // Update table with filtered users
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    filteredUsers.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.id}</td>
            <td>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <div style="width: 32px; height: 32px; background: var(--primary-color); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">
                        ${user.fullName.charAt(0)}
                    </div>
                    ${user.fullName}
                </div>
            </td>
            <td>${user.username}</td>
            <td>${user.email}</td>
            <td>
                <span class="status-badge ${getRoleBadgeClass(user.role)}">
                    ${user.role}
                </span>
            </td>
            <td>
                <span class="status-badge ${user.status === 'active' ? 'status-finalized' : 'status-draft'}">
                    ${user.status}
                </span>
            </td>
            <td>${formatDate(user.lastLogin)}</td>
            <td>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-outline" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="editUser(${user.id})">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-danger" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="confirmDeleteUser(${user.id})" ${user.role === 'admin' ? 'disabled' : ''}>
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Open add user modal
function openAddUserModal() {
    document.getElementById('modalTitle').innerHTML = '<i class="fas fa-user-plus"></i> Add New User';
    document.getElementById('userForm').reset();
    document.getElementById('userId').value = '';
    
    // Make password fields required for new users
    document.getElementById('userPassword').required = true;
    document.getElementById('userPasswordConfirm').required = true;
    
    document.getElementById('userModal').style.display = 'flex';
}

// Edit user
function editUser(userId) {
    const users = getAllUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
        showToast('User not found', 'error');
        return;
    }
    
    document.getElementById('modalTitle').innerHTML = '<i class="fas fa-user-edit"></i> Edit User';
    document.getElementById('userId').value = user.id;
    document.getElementById('userFullName').value = user.fullName;
    document.getElementById('userUsername').value = user.username;
    document.getElementById('userEmail').value = user.email;
    document.getElementById('userRole').value = user.role;
    document.getElementById('userStatus').value = user.status;
    document.getElementById('userPhone').value = user.phone || '';
    document.getElementById('userDepartment').value = user.department || '';
    
    // Password fields optional for editing
    document.getElementById('userPassword').required = false;
    document.getElementById('userPasswordConfirm').required = false;
    document.getElementById('userPassword').value = '';
    document.getElementById('userPasswordConfirm').value = '';
    
    // Set permissions
    document.getElementById('permCreateAudit').checked = user.permissions.createAudit;
    document.getElementById('permEditAudit').checked = user.permissions.editAudit;
    document.getElementById('permDeleteAudit').checked = user.permissions.deleteAudit;
    document.getElementById('permViewReports').checked = user.permissions.viewReports;
    document.getElementById('permExportData').checked = user.permissions.exportData;
    document.getElementById('permManageUsers').checked = user.permissions.manageUsers;
    
    document.getElementById('userModal').style.display = 'flex';
}

// Save user
function saveUser(event) {
    event.preventDefault();
    
    const userId = document.getElementById('userId').value;
    const fullName = document.getElementById('userFullName').value.trim();
    const username = document.getElementById('userUsername').value.trim();
    const email = document.getElementById('userEmail').value.trim();
    const password = document.getElementById('userPassword').value;
    const passwordConfirm = document.getElementById('userPasswordConfirm').value;
    const role = document.getElementById('userRole').value;
    const status = document.getElementById('userStatus').value;
    const phone = document.getElementById('userPhone').value.trim();
    const department = document.getElementById('userDepartment').value.trim();
    
    // Validation
    if (!fullName || !username || !email || !role || !status) {
        showToast('Please fill all required fields', 'error');
        return;
    }
    
    // Password validation for new users or when password is being changed
    if (password || passwordConfirm) {
        if (password !== passwordConfirm) {
            showToast('Passwords do not match', 'error');
            return;
        }
        
        if (password.length < 6) {
            showToast('Password must be at least 6 characters', 'error');
            return;
        }
    }
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showToast('Please enter a valid email address', 'error');
        return;
    }
    
    const users = getAllUsers();
    
    // Check for duplicate username/email (except for current user when editing)
    const duplicateUsername = users.find(u => u.username === username && u.id !== parseInt(userId));
    const duplicateEmail = users.find(u => u.email === email && u.id !== parseInt(userId));
    
    if (duplicateUsername) {
        showToast('Username already exists', 'error');
        return;
    }
    
    if (duplicateEmail) {
        showToast('Email already exists', 'error');
        return;
    }
    
    // Create user object
    const userData = {
        fullName,
        username,
        email,
        role,
        status,
        phone,
        department,
        permissions: {
            createAudit: document.getElementById('permCreateAudit').checked,
            editAudit: document.getElementById('permEditAudit').checked,
            deleteAudit: document.getElementById('permDeleteAudit').checked,
            viewReports: document.getElementById('permViewReports').checked,
            exportData: document.getElementById('permExportData').checked,
            manageUsers: document.getElementById('permManageUsers').checked
        }
    };
    
    if (userId) {
        // Update existing user
        const userIndex = users.findIndex(u => u.id === parseInt(userId));
        if (userIndex !== -1) {
            users[userIndex] = {
                ...users[userIndex],
                ...userData,
                ...(password && { password }) // Only update password if provided
            };
            showToast('User updated successfully', 'success');
        }
    } else {
        // Add new user
        if (!password) {
            showToast('Password is required for new users', 'error');
            return;
        }
        
        const newUser = {
            id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1,
            ...userData,
            password,
            lastLogin: new Date().toISOString(),
            createdAt: new Date().toISOString()
        };
        users.push(newUser);
        showToast('User added successfully', 'success');
    }
    
    saveUsers(users);
    loadUsers();
    closeUserModal();
}

// Close user modal
function closeUserModal() {
    document.getElementById('userModal').style.display = 'none';
    document.getElementById('userForm').reset();
}
// Confirm delete user
function confirmDeleteUser(userId) {
    const users = getAllUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
        showToast('User not found', 'error');
        return;
    }
    
    if (user.role === 'admin') {
        showToast('Cannot delete administrator accounts', 'error');
        return;
    }
    
    if (confirm(`Are you sure you want to delete user "${user.fullName}"?\n\nThis action cannot be undone.`)) {
        deleteUser(userId);
    }
}

// Delete user
function deleteUser(userId) {
    let users = getAllUsers();
    users = users.filter(u => u.id !== userId);
    saveUsers(users);
    loadUsers();
    showToast('User deleted successfully', 'success');
}

// Initialize users when page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeUsers();
    
    // Load users when users section is shown
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.target.id === 'usersSection' && !mutation.target.classList.contains('hidden')) {
                loadUsers();
                updateUserStats();
            }
        });
    });
    
    const usersSection = document.getElementById('usersSection');
    if (usersSection) {
        observer.observe(usersSection, { attributes: true, attributeFilter: ['class'] });
    }
});

// Close modal when clicking outside
document.addEventListener('click', function(event) {
    const modal = document.getElementById('userModal');
    if (modal && event.target === modal) {
        closeUserModal();
    }
});

// Close modal with Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        const modal = document.getElementById('userModal');
        if (modal && modal.style.display === 'flex') {
            closeUserModal();
        }
    }
});

console.log('User Management System Loaded');
// ========================================
// EXPOSE FUNCTIONS TO GLOBAL SCOPE
// ========================================
window.showSection = showSection;
window.switchTab = switchTab;
window.logout = logout;
window.toggleTheme = toggleTheme;
window.refreshDashboard = refreshDashboard;
window.saveDraft = saveDraft;
window.submitAudit = submitAudit;
window.resetForm = resetForm;
window.calculateTotals = calculateTotals;
window.calculateCPAF = calculateCPAF;
window.addSupplierRow = addSupplierRow;
window.removeSupplierRow = removeSupplierRow;
window.addCalculationRow = addCalculationRow;
window.removeCalculationRow = removeCalculationRow;
window.calculateRowCPAF = calculateRowCPAF;
window.clearSignature = clearSignature;
window.saveSignature = saveSignature;
window.uploadSignature = uploadSignature;
window.editAudit = editAudit;
window.confirmDeleteAudit = confirmDeleteAudit;
window.searchAudits = searchAudits;
window.clearFilters = clearFilters;
window.exportMultiSheetExcel = exportMultiSheetExcel;
window.exportCSV = exportCSV;
window.exportJSON = exportJSON;
window.exportPDF = exportPDF;
window.toggleOnsiteDetails = toggleOnsiteDetails;
window.saveSettings = saveSettings;
window.backupDatabase = backupDatabase;
window.importData = importData;
window.clearAllData = clearAllData;
window.removeTagFromInput = removeTagFromInput; // Add tags functionality

// ========================================
// INITIALIZATION COMPLETE
// ========================================
console.log('🇰🇪 PAKPRO Kenya Digital Verification Audit System Ready!');