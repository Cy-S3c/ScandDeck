/**
 * ScandDeck Web Interface
 * Main application JavaScript file for handling UI interactions,
 * API communication, and dynamic content updates.
 */

// Global state management
const scandeckApp = {
    currentView: 'dashboard',
    scanHistory: [],
    activeScans: [],
    scanResults: {},
    notifications: [],
    targets: [],
    scanConfigs: []
};

// DOM ready initialization
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
    navigateTo('dashboard');
    fetchInitialData();
});

/**
 * Initialize the application
 */
function initializeApp() {
    console.log('ScandDeck UI Initializing...');
    
    // Check if API is available
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'ok') {
                updateStatusIndicator(true, 'Connected to ScandDeck API');
            } else {
                updateStatusIndicator(false, 'API connection issues');
            }
        })
        .catch(error => {
            console.error('API Status Check Failed:', error);
            updateStatusIndicator(false, 'Cannot connect to API');
        });
        
    // Setup periodic data refresh
    setInterval(refreshActiveScans, 5000);
    setInterval(checkNotifications, 30000);
}

/**
 * Set up all event listeners for the UI
 */
function setupEventListeners() {
    // Navigation menu links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const view = e.target.dataset.view;
            navigateTo(view);
        });
    });
    
    // Scan form submission
    const scanForm = document.getElementById('new-scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', handleNewScan);
    }
    
    // Target selection in scan configuration
    const targetSelect = document.getElementById('scan-target');
    if (targetSelect) {
        targetSelect.addEventListener('change', updateTargetInfo);
    }
    
    // Scan template selection
    const templateSelect = document.getElementById('scan-template');
    if (templateSelect) {
        templateSelect.addEventListener('change', loadScanTemplate);
    }
    
    // Add target button
    const addTargetBtn = document.getElementById('add-target-btn');
    if (addTargetBtn) {
        addTargetBtn.addEventListener('click', showAddTargetModal);
    }
    
    // Save config button
    const saveConfigBtn = document.getElementById('save-config-btn');
    if (saveConfigBtn) {
        saveConfigBtn.addEventListener('click', saveScanConfiguration);
    }

    // Results filter change
    const resultsFilter = document.getElementById('results-filter');
    if (resultsFilter) {
        resultsFilter.addEventListener('change', filterResults);
    }
    
    // Logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
}

/**
 * Handle navigation between different views
 * @param {string} viewName - The name of the view to navigate to
 */
function navigateTo(viewName) {
    // Hide all views
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.add('d-none');
    });
    
    // Show the selected view
    const selectedView = document.getElementById(`${viewName}-view`);
    if (selectedView) {
        selectedView.classList.remove('d-none');
    }
    
    // Update active navigation link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.dataset.view === viewName) {
            link.classList.add('active');
        }
    });
    
    scandeckApp.currentView = viewName;
    
    // Perform view-specific data loading
    switch (viewName) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'scan':
            loadScanConfigurations();
            loadTargetsList();
            break;
        case 'results':
            loadScanResults();
            break;
        case 'history':
            loadScanHistory();
            break;
    }
}

/**
 * Fetch initial data required for the application
 */
function fetchInitialData() {
    // Fetch targets
    fetch('/api/targets')
        .then(response => response.json())
        .then(data => {
            scandeckApp.targets = data.targets;
            updateTargetsDropdowns();
        })
        .catch(error => console.error('Error fetching targets:', error));
    
    // Fetch scan configurations
    fetch('/api/scan-configs')
        .then(response => response.json())
        .then(data => {
            scandeckApp.scanConfigs = data.configurations;
            updateConfigurationsDropdowns();
        })
        .catch(error => console.error('Error fetching scan configurations:', error));
    
    // Fetch active scans
    refreshActiveScans();
    
    // Fetch recent scan history
    fetch('/api/scans/history?limit=5')
        .then(response => response.json())
        .then(data => {
            scandeckApp.scanHistory = data.history;
            updateRecentScansWidget();
        })
        .catch(error => console.error('Error fetching scan history:', error));
}

/**
 * Update the status indicator in the UI
 * @param {boolean} isConnected - Whether the API is connected
 * @param {string} message - Status message to display
 */
function updateStatusIndicator(isConnected, message) {
    const statusIndicator = document.getElementById('api-status');
    if (statusIndicator) {
        statusIndicator.className = isConnected ? 'status-indicator connected' : 'status-indicator disconnected';
        statusIndicator.setAttribute('title', message);
        statusIndicator.querySelector('span').textContent = isConnected ? 'Connected' : 'Disconnected';
    }
}

/**
 * Load and display dashboard data
 */
function loadDashboardData() {
    // Update recent scans widget
    updateRecentScansWidget();
    
    // Update active scans widget
    updateActiveScansWidget();
    
    // Update system status widget
    fetch('/api/system/status')
        .then(response => response.json())
        .then(data => {
            updateSystemStatusWidget(data);
        })
        .catch(error => console.error('Error fetching system status:', error));
    
    // Update discovered vulnerabilities widget
    fetch('/api/vulnerabilities/summary')
        .then(response => response.json())
        .then(data => {
            updateVulnerabilitiesWidget(data);
        })
        .catch(error => console.error('Error fetching vulnerabilities summary:', error));
}

/**
 * Load scan configuration data
 */
function loadScanConfigurations() {
    fetch('/api/scan-configs')
        .then(response => response.json())
        .then(data => {
            scandeckApp.scanConfigs = data.configurations;
            const templateSelect = document.getElementById('scan-template');
            if (templateSelect) {
                // Clear existing options
                templateSelect.innerHTML = '<option value="">Select a template...</option>';
                
                // Add options for each configuration
                data.configurations.forEach(config => {
                    const option = document.createElement('option');
                    option.value = config.id;
                    option.textContent = config.name;
                    templateSelect.appendChild(option);
                });
            }
        })
        .catch(error => console.error('Error loading scan configurations:', error));
}

/**
 * Load available targets list
 */
function loadTargetsList() {
    fetch('/api/targets')
        .then(response => response.json())
        .then(data => {
            scandeckApp.targets = data.targets;
            const targetSelect = document.getElementById('scan-target');
            if (targetSelect) {
                // Clear existing options
                targetSelect.innerHTML = '<option value="">Select a target...</option>';
                
                // Add options for each target
                data.targets.forEach(target => {
                    const option = document.createElement('option');
                    option.value = target.id;
                    option.textContent = target.name;
                    targetSelect.appendChild(option);
                });
            }
            
            // Update targets table if it exists
            updateTargetsTable(data.targets);
        })
        .catch(error => console.error('Error loading targets list:', error));
}

/**
 * Update targets table with the latest data
 * @param {Array} targets - List of targets to display
 */
function updateTargetsTable(targets) {
    const targetsTable = document.getElementById('targets-table-body');
    if (targetsTable) {
        targetsTable.innerHTML = '';
        
        targets.forEach(target => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${target.name}</td>
                <td>${target.type}</td>
                <td>${target.address}</td>
                <td>${target.lastScan || 'Never'}</td>
                <td>
                    <button class="btn btn-sm btn-primary scan-target-btn" data-target-id="${target.id}">
                        <i class="fas fa-search"></i> Scan
                    </button>
                    <button class="btn btn-sm btn-danger delete-target-btn" data-target-id="${target.id}">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            `;
            targetsTable.appendChild(row);
        });
        
        // Add event listeners for the new buttons
        document.querySelectorAll('.scan-target-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const targetId = e.target.closest('button').dataset.targetId;
                navigateTo('scan');
                document.getElementById('scan-target').value = targetId;
                updateTargetInfo();
            });
        });
        
        document.querySelectorAll('.delete-target-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const targetId = e.target.closest('button').dataset.targetId;
                deleteTarget(targetId);
            });
        });
    }
}

/**
 * Handle submission of a new scan
 * @param {Event} e - Form submission event
 */
function handleNewScan(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const scanData = {
        targetId: formData.get('target'),
        configId: formData.get('template') || null,
        customScan: formData.get('template') ? false : true,
        options: {
            ports: formData.get('ports'),
            techniques: Array.from(document.querySelectorAll('input[name="techniques"]:checked')).map(el => el.value),
            intensity: formData.get('intensity'),
            serviceDetection: formData.get('service-detection') === 'on',
            vulnerabilityCheck: formData.get('vulnerability-check') === 'on'
        }
    };
    
    // Validate the form data
    if (!scanData.targetId) {
        showNotification('Please select a target', 'error');
        return;
    }
    
    // Show loading state
    const submitButton = document.getElementById('start-scan-btn');
    submitButton.disabled = true;
    submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Starting...';
    
    // Send the scan request to the API
    fetch('/api/scans/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(scanData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(`Scan started successfully. Scan ID: ${data.scanId}`, 'success');
            
            // Add to active scans
            scandeckApp.activeScans.push({
                id: data.scanId,
                targetName: document.getElementById('scan-target').options[document.getElementById('scan-target').selectedIndex].text,
                status: 'initializing',
                progress: 0,
                startTime: new Date().toISOString()
            });
            
            // Update UI
            updateActiveScansWidget();
            
            // Navigate to dashboard to show progress
            navigateTo('dashboard');
        } else {
            showNotification(`Failed to start scan: ${data.error}`, 'error');
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        showNotification('An error occurred while trying to start the scan', 'error');
    })
    .finally(() => {
        // Reset button state
        submitButton.disabled = false;
        submitButton.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    });
}

/**
 * Load a scan configuration template
 */
function loadScanTemplate() {
    const templateId = document.getElementById('scan-template').value;
    if (!templateId) return;
    
    const selectedConfig = scandeckApp.scanConfigs.find(config => config.id === templateId);
    if (!selectedConfig) return;
    
    // Populate the form with the template values
    document.getElementById('ports').value = selectedConfig.ports || '';
    
    // Set techniques checkboxes
    document.querySelectorAll('input[name="techniques"]').forEach(checkbox => {
        checkbox.checked = selectedConfig.techniques.includes(checkbox.value);
    });
    
    // Set intensity slider
    document.getElementById('intensity').value = selectedConfig.intensity || 5;
    document.getElementById('intensity-value').textContent = selectedConfig.intensity || 5;
    
    // Set other options
    document.getElementById('service-detection').checked = selectedConfig.serviceDetection || false;
    document.getElementById('vulnerability-check').checked = selectedConfig.vulnerabilityCheck || false;
    
    showNotification(`Loaded scan template: ${selectedConfig.name}`, 'info');
}

/**
 * Update information about the selected target
 */
function updateTargetInfo() {
    const targetId = document.getElementById('scan-target').value;
    if (!targetId) return;
    
    const selectedTarget = scandeckApp.targets.find(target => target.id === targetId);
    if (!selectedTarget) return;
    
    const targetInfoDiv = document.getElementById('target-info');
    if (targetInfoDiv) {
        targetInfoDiv.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h5>Target Information</h5>
                </div>
                <div class="card-body">
                    <p><strong>Name:</strong> ${selectedTarget.name}</p>
                    <p><strong>Type:</strong> ${selectedTarget.type}</p>
                    <p><strong>Address:</strong> ${selectedTarget.address}</p>
                    <p><strong>Last Scanned:</strong> ${selectedTarget.lastScan || 'Never'}</p>
                </div>
            </div>
        `;
    }
}

/**
 * Show modal for adding a new target
 */
function showAddTargetModal() {
    const modalHtml = `
        <div class="modal fade" id="

