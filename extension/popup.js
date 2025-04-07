document.addEventListener('DOMContentLoaded', async () => {
  const root = document.getElementById('root');
  
  // Initialize stats
  let stats = await getStats();
  
  // Initial UI rendering
  renderUI(stats);
  
  // Get the current tab URL
  const tabs = await chrome.tabs.query({active: true, currentWindow: true});
  const currentUrl = tabs[0].url;
  
  // Check if the URL is in the safe/threat cache
  chrome.storage.local.get(['safeUrls', 'threatUrls', 'darkTheme'], (result) => {
    const safeUrls = result.safeUrls || [];
    const threatUrls = result.threatUrls || [];
    
    // Apply dark theme if enabled
    if (result.darkTheme) {
      document.body.classList.add('dark-theme');
      document.getElementById('themeToggle').textContent = '☀️';
    } else {
      document.getElementById('themeToggle').textContent = '🌙';
    }
    
    if (safeUrls.includes(currentUrl)) {
      updateUIStatus('safe', 'This website is safe to browse.');
    } else if (threatUrls.some(threat => threat.url === currentUrl)) {
      const threatInfo = threatUrls.find(threat => threat.url === currentUrl);
      updateUIStatus('danger', 'Threat detected on this website!');
      showThreatDetails(threatInfo);
    } else {
      // If not in cache, scan the website
      updateUIStatus('warning', 'Scanning website...');
      scanWebsite(currentUrl);
    }
  });
  
  // Event listeners
  document.addEventListener('click', (e) => {
    if (e.target.id === 'settingsBtn') {
      toggleSettings();
    } else if (e.target.id === 'blockBtn') {
      blockCurrentSite();
    } else if (e.target.id === 'detailsBtn') {
      toggleThreatDetails();
    } else if (e.target.id === 'themeToggle') {
      toggleTheme();
    } else if (e.target.id === 'clearStatsBtn') {
      showClearStatsConfirmation();
    } else if (e.target.id === 'confirmClearStats') {
      clearStats();
      hideClearStatsConfirmation();
    } else if (e.target.id === 'cancelClearStats') {
      hideClearStatsConfirmation();
    }
  });
});

// Get stats from storage
async function getStats() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['safeUrls', 'threatUrls', 'scanCount'], (result) => {
      const safeUrls = result.safeUrls || [];
      const threatUrls = result.threatUrls || [];
      const scanCount = result.scanCount || 0;
      
      resolve({
        safe: safeUrls.length,
        threats: threatUrls.length,
        total: scanCount
      });
    });
  });
}

// Update stats
async function updateStats(isThreat) {
  const stats = await getStats();
  
  // Increment total scan count
  stats.total += 1;
  
  // Increment appropriate counter
  if (isThreat) {
    stats.threats += 1;
  } else {
    stats.safe += 1;
  }
  
  // Save updated stats
  chrome.storage.local.set({ scanCount: stats.total });
  
  // Update UI
  updateStatsUI(stats);
  
  return stats;
}

// Clear all stats
async function clearStats() {
  chrome.storage.local.set({ 
    scanCount: 0,
    safeUrls: [],
    threatUrls: []
  }, async () => {
    const stats = await getStats();
    updateStatsUI(stats);
  });
}

// Show confirmation dialog for clearing stats
function showClearStatsConfirmation() {
  const dialog = document.createElement('div');
  dialog.className = 'confirmation-dialog';
  dialog.id = 'clearStatsDialog';
  dialog.innerHTML = `
    <div class="dialog-content">
      <div class="dialog-title">Clear All Statistics</div>
      <p>Are you sure you want to clear all browsing statistics? This will reset all counters and cached URLs.</p>
      <div class="dialog-actions">
        <button id="cancelClearStats" class="secondary">Cancel</button>
        <button id="confirmClearStats" class="danger">Clear All</button>
      </div>
    </div>
  `;
  document.body.appendChild(dialog);
}

// Hide confirmation dialog
function hideClearStatsConfirmation() {
  const dialog = document.getElementById('clearStatsDialog');
  if (dialog) {
    dialog.remove();
  }
}

// Render main UI
function renderUI(stats = { safe: 0, threats: 0, total: 0 }) {
  root.innerHTML = `
    <div class="container">
      <div class="header">
        <h1>CipherLens</h1>
        <div id="statusIndicator" class="status warning">
          <span class="status-icon">⚠️</span>
          <span id="statusMessage">Initializing...</span>
        </div>
        <div id="themeToggle" class="theme-toggle">🌙</div>
        <div id="settingsBtn" class="settings-icon">⚙️</div>
      </div>
      
      <div class="content">
        <div class="stats-container">
          <div class="stat-item">
            <div id="safeCount" class="stat-value">${stats.safe}</div>
            <div class="stat-label">Safe Sites</div>
          </div>
          <div class="stat-item">
            <div id="threatCount" class="stat-value">${stats.threats}</div>
            <div class="stat-label">Threats</div>
          </div>
          <div class="stat-item">
            <div id="totalCount" class="stat-value">${stats.total}</div>
            <div class="stat-label">Total Scans</div>
          </div>
        </div>
        
        <div id="threatDetailsContainer"></div>
      </div>
      
      <div class="navigation">
        <button id="navHome" class="nav-btn active">
          <span class="nav-icon">🏠</span>
          <span class="nav-label">Home</span>
        </button>
        <button id="navHistory" class="nav-btn">
          <span class="nav-icon">📋</span>
          <span class="nav-label">History</span>
        </button>
        <button id="navReport" class="nav-btn">
          <span class="nav-icon">📊</span>
          <span class="nav-label">Reports</span>
        </button>
        <button id="navPasswordChecker" class="nav-btn">
          <span class="nav-icon">🔑</span>
          <span class="nav-label">Passwords</span>
        </button>
      </div>
      
      <div class="footer">
        <button id="detailsBtn" class="primary">
          <span>Details</span>
        </button>
        <button id="blockBtn" class="danger">
          <span>Block Page</span>
        </button>
      </div>
    </div>
  `;
  
  // Add navigation event listeners
  document.getElementById('navHome').addEventListener('click', () => {
    setActiveNavButton('navHome');
    
    // Re-render the main content and re-scan current page
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      const currentUrl = tabs[0].url;
      
      chrome.storage.local.get(['safeUrls', 'threatUrls', 'scanCount'], (result) => {
        const stats = {
          safe: (result.safeUrls || []).length,
          threats: (result.threatUrls || []).length,
          total: result.scanCount || 0
        };
        
        // First, restore the content structure with stats container
        const content = document.querySelector('.content');
        content.innerHTML = `
          <div class="stats-container">
            <div class="stat-item">
              <div id="safeCount" class="stat-value">${stats.safe}</div>
              <div class="stat-label">Safe Sites</div>
            </div>
            <div class="stat-item">
              <div id="threatCount" class="stat-value">${stats.threats}</div>
              <div class="stat-label">Threats</div>
            </div>
            <div class="stat-item">
              <div id="totalCount" class="stat-value">${stats.total}</div>
              <div class="stat-label">Total Scans</div>
            </div>
          </div>
          
          <div id="threatDetailsContainer"></div>
        `;
        
        // Check URL status
        const safeUrls = result.safeUrls || [];
        const threatUrls = result.threatUrls || [];
        
        if (safeUrls.includes(currentUrl)) {
          updateUIStatus('safe', 'This website is safe to browse.');
        } else if (threatUrls.some(threat => threat.url === currentUrl)) {
          const threatInfo = threatUrls.find(threat => threat.url === currentUrl);
          updateUIStatus('danger', 'Threat detected on this website!');
          showThreatDetails(threatInfo);
        } else {
          updateUIStatus('warning', 'Scanning website...');
          scanWebsite(currentUrl);
        }
      });
    });
  });
  
  document.getElementById('navHistory').addEventListener('click', () => {
    setActiveNavButton('navHistory');
    showHistory();
  });
  
  document.getElementById('navPasswordChecker').addEventListener('click', () => {
    setActiveNavButton('navPasswordChecker');
    showPasswordChecker();
  });
  
  document.getElementById('navReport').addEventListener('click', () => {
    setActiveNavButton('navReport');
    showReports();
  });
}

// Helper function to set active navigation button
function setActiveNavButton(buttonId) {
  document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
  document.getElementById(buttonId).classList.add('active');
}

// Show reports section
function showReports() {
  const content = document.querySelector('.content');
  
  chrome.storage.local.get(['safeUrls', 'threatUrls', 'scanCount'], (result) => {
    const safeUrls = result.safeUrls || [];
    const threatUrls = result.threatUrls || [];
    const scanCount = result.scanCount || 0;
    
    // Calculate percentages
    const safePercent = scanCount > 0 ? Math.round((safeUrls.length / scanCount) * 100) : 0;
    const threatPercent = scanCount > 0 ? Math.round((threatUrls.length / scanCount) * 100) : 0;
    
    // Calculate threat types (in a real implementation, this would be more detailed)
    const phishingCount = threatUrls.filter(t => t.type === 'Potential Phishing').length;
    const malwareCount = threatUrls.length - phishingCount;
    
    content.innerHTML = `
      <div class="reports-container">
        <h2>Security Reports</h2>
        
        <div class="report-section">
          <h3>Overview</h3>
          <div class="report-card">
            <div class="report-stat">
              <div class="report-value">${scanCount}</div>
              <div class="report-label">Total Scans</div>
            </div>
            <div class="report-chart">
              <div class="chart-safe" style="width: ${safePercent}%"></div>
              <div class="chart-threat" style="width: ${threatPercent}%"></div>
            </div>
            <div class="chart-legend">
              <div class="legend-item">
                <div class="legend-color safe"></div>
                <div>Safe (${safePercent}%)</div>
              </div>
              <div class="legend-item">
                <div class="legend-color threat"></div>
                <div>Threats (${threatPercent}%)</div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="report-section">
          <h3>Threat Breakdown</h3>
          <div class="threat-breakdown">
            <div class="breakdown-item">
              <div class="breakdown-label">Phishing</div>
              <div class="breakdown-bar">
                <div class="breakdown-progress" style="width: ${phishingCount > 0 ? (phishingCount / threatUrls.length) * 100 : 0}%"></div>
              </div>
              <div class="breakdown-value">${phishingCount}</div>
            </div>
            <div class="breakdown-item">
              <div class="breakdown-label">Malware</div>
              <div class="breakdown-bar">
                <div class="breakdown-progress" style="width: ${malwareCount > 0 ? (malwareCount / threatUrls.length) * 100 : 0}%"></div>
              </div>
              <div class="breakdown-value">${malwareCount}</div>
            </div>
          </div>
        </div>
        
        <div class="report-actions">
          <button id="exportReportBtn" class="secondary">Export Report</button>
        </div>
      </div>
    `;
    
    // Add export report functionality
    document.getElementById('exportReportBtn').addEventListener('click', () => {
      // In a real implementation, this would generate a PDF or CSV report
      alert('Report exported (demo)');
    });
  });
}

// Update UI with status
function updateUIStatus(status, message) {
  const statusIndicator = document.getElementById('statusIndicator');
  const statusMessage = document.getElementById('statusMessage');
  
  // Remove existing status classes
  statusIndicator.classList.remove('safe', 'danger', 'warning');
  
  // Add appropriate status class
  statusIndicator.classList.add(status);
  
  // Update status icon
  let icon = '⚠️';
  if (status === 'safe') icon = '✅';
  if (status === 'danger') icon = '⛔';
  
  // Update status message
  statusIndicator.innerHTML = `<span class="status-icon">${icon}</span><span id="statusMessage">${message}</span>`;
}

// Update stats in UI
function updateStatsUI(stats) {
  document.getElementById('safeCount').textContent = stats.safe;
  document.getElementById('threatCount').textContent = stats.threats;
  document.getElementById('totalCount').textContent = stats.total;
}

// Show threat details
function showThreatDetails(threatInfo) {
  const container = document.getElementById('threatDetailsContainer');
  
  if (!threatInfo) {
    container.innerHTML = '';
    return;
  }
  
  container.innerHTML = `
    <div class="threat-details">
      <div class="threat-header">Threat Details</div>
      
      <div class="threat-item">
        <div class="threat-icon">🔍</div>
        <div class="threat-text">
          <strong>Type:</strong> ${threatInfo.type}
        </div>
      </div>
      
      <div class="threat-item">
        <div class="threat-icon">⚠️</div>
        <div class="threat-text">
          <strong>Risk Level:</strong> ${threatInfo.riskLevel}
        </div>
      </div>
      
      <div class="threat-item">
        <div class="threat-icon">ℹ️</div>
        <div class="threat-text">
          <strong>Details:</strong> ${threatInfo.details}
        </div>
      </div>
      
      ${threatInfo.flaggedElements && threatInfo.flaggedElements.length > 0 ? `
        <div class="threat-item">
          <div class="threat-icon">🚫</div>
          <div class="threat-text">
            <strong>Flagged Elements:</strong>
            <div class="flagged-elements">
              ${threatInfo.flaggedElements.map(element => 
                `<div class="flagged-element-item">${element}</div>`
              ).join('')}
            </div>
          </div>
        </div>
      ` : ''}
    </div>
  `;
}

// Toggle settings menu
function toggleSettings() {
  const content = document.querySelector('.content');
  
  if (content.querySelector('.settings-menu')) {
    // If settings are already open, close them
    chrome.storage.local.get(['safeUrls', 'threatUrls', 'scanCount'], async (result) => {
      const stats = {
        safe: (result.safeUrls || []).length,
        threats: (result.threatUrls || []).length,
        total: result.scanCount || 0
      };
      
      renderUI(stats);
      
      // Re-check the current URL
      const tabs = await chrome.tabs.query({active: true, currentWindow: true});
      const currentUrl = tabs[0].url;
      
      chrome.storage.local.get(['safeUrls', 'threatUrls'], (result) => {
        const safeUrls = result.safeUrls || [];
        const threatUrls = result.threatUrls || [];
        
        if (safeUrls.includes(currentUrl)) {
          updateUIStatus('safe', 'This website is safe to browse.');
        } else if (threatUrls.some(threat => threat.url === currentUrl)) {
          const threatInfo = threatUrls.find(threat => threat.url === currentUrl);
          updateUIStatus('danger', 'Threat detected on this website!');
          showThreatDetails(threatInfo);
        }
      });
    });
  } else {
    // Open settings
    content.innerHTML = `
      <div class="settings-menu">
        <h2>Settings</h2>
        
        <div class="setting-item">
          <div>
            <div class="setting-label">Dark Mode</div>
            <div class="setting-description">Toggle between light and dark theme</div>
          </div>
          <label class="switch">
            <input type="checkbox" id="darkModeToggle" ${document.body.classList.contains('dark-theme') ? 'checked' : ''}>
            <span class="slider"></span>
          </label>
        </div>
        
        <div class="setting-item">
          <div>
            <div class="setting-label">Enhanced Protection</div>
            <div class="setting-description">Enable more aggressive phishing detection</div>
          </div>
          <label class="switch">
            <input type="checkbox" id="enhancedProtectionToggle" checked>
            <span class="slider"></span>
          </label>
        </div>
        
        <div class="setting-item">
          <div>
            <div class="setting-label">Auto-Block Threats</div>
            <div class="setting-description">Automatically block detected threats</div>
          </div>
          <label class="switch">
            <input type="checkbox" id="autoBlockToggle">
            <span class="slider"></span>
          </label>
        </div>
        
        <button id="clearStatsBtn" class="danger" style="margin-top: 20px; width: 100%;">
          Clear Statistics
        </button>
      </div>
    `;
    
    // Add event listener for dark mode toggle in settings
    document.getElementById('darkModeToggle').addEventListener('change', (e) => {
      toggleTheme(e.target.checked);
    });
  }
}

// Toggle dark/light theme
function toggleTheme(forceDark) {
  const isDark = typeof forceDark !== 'undefined' ? forceDark : !document.body.classList.contains('dark-theme');
  const themeToggle = document.getElementById('themeToggle');
  
  if (isDark) {
    document.body.classList.add('dark-theme');
    themeToggle.textContent = '☀️';
  } else {
    document.body.classList.remove('dark-theme');
    themeToggle.textContent = '🌙';
  }
  
  chrome.storage.local.set({darkTheme: isDark});
}

// Scan website for threats
function scanWebsite(url) {
  // First get content analysis data from the current page
  chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    const currentTab = tabs[0];
    
    // Show scanning indicator
    updateUIStatus('warning', 'Scanning website...');
    
    // Try to get content analysis via content script
    try {
      chrome.tabs.sendMessage(currentTab.id, {action: 'scanPage'}, (contentData) => {
        // If content script responded, combine URL and content analysis
        if (contentData && !chrome.runtime.lastError) {
          // Make API call to Python backend with both URL and content
          callDetectionAPI(url, contentData);
        } else {
          // If content script didn't respond, fall back to URL-only analysis
          callDetectionAPI(url);
        }
      });
    } catch (error) {
      // If any error occurs with content script, fall back to URL-only analysis
      console.error('Error with content script:', error);
      callDetectionAPI(url);
    }
  });
}

// Call detection API with appropriate data
function callDetectionAPI(url, contentData = null) {
  // Prepare the API endpoint and data
  let endpoint = 'http://localhost:5000/api/detect/url';
  let postData = { url: url };
  
  // If we have content data, use the content endpoint
  if (contentData) {
    endpoint = 'http://localhost:5000/api/detect/content';
    postData = { 
      url: url,
      content: contentData
    };
  }
  
  // Make the API call
  fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(postData),
  })
  .then(response => {
    if (!response.ok) {
      throw new Error(`API responded with status: ${response.status}`);
    }
    return response.json();
  })
  .then(data => {
    processDetectionResult(url, data);
  })
  .catch(error => {
    console.error('Error calling API:', error);
    // Show connection error message
    updateUIStatus('warning', 'Could not connect to detection service. Using local detection...');
    // Fall back to local detection after a short delay
    setTimeout(() => simulateDetection(url), 1000);
  });
}

// Process detection result from API
function processDetectionResult(url, data) {
  if (data.success && data.result) {
    const isPhishing = data.result.isPhishing;
    const threatLevel = data.result.threatLevel || 'Medium';
    const explanations = data.result.explanations || [];
    const score = data.result.score || 0;
    
    if (isPhishing) {
      const threatInfo = {
        url: url,
        type: 'Potential Phishing',
        riskLevel: threatLevel,
        score: score,
        timestamp: new Date().toISOString(),
        details: explanations[0] || 'This website exhibits characteristics commonly associated with phishing attempts.',
        flaggedElements: explanations.slice(1) || [
          'Suspicious domain pattern detected',
          'Insecure connection'
        ]
      };
      
      // Cache the threat
      chrome.storage.local.get(['threatUrls'], (result) => {
        const threatUrls = result.threatUrls || [];
        // Check if URL already exists in threats
        const existingIndex = threatUrls.findIndex(t => t.url === url);
        
        if (existingIndex >= 0) {
          // Update existing threat
          threatUrls[existingIndex] = threatInfo;
        } else {
          // Add new threat
          threatUrls.push(threatInfo);
        }
        
        chrome.storage.local.set({threatUrls}, async () => {
          updateUIStatus('danger', 'Threat detected on this website!');
          showThreatDetails(threatInfo);
          await updateStats(true);
          
          // Notify background script about the threat
          chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            chrome.runtime.sendMessage({
              action: 'threatDetected',
              tabId: tabs[0].id,
              url: url
            });
          });
        });
      });
    } else {
      // Cache the safe URL
      chrome.storage.local.get(['safeUrls'], (result) => {
        const safeUrls = result.safeUrls || [];
        // Only add if not already in the list
        if (!safeUrls.includes(url)) {
          safeUrls.push(url);
        }
        
        chrome.storage.local.set({safeUrls}, async () => {
          updateUIStatus('safe', 'This website is safe to browse.');
          
          // Clear threat details
          document.getElementById('threatDetailsContainer').innerHTML = '';
          
          await updateStats(false);
          
          // Notify background script about the safe site
          chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            chrome.runtime.sendMessage({
              action: 'safeSiteDetected',
              tabId: tabs[0].id,
              url: url
            });
          });
        });
      });
    }
  } else {
    console.error('Invalid API response:', data);
    // API error or no result, fall back to simulation
    simulateDetection(url);
  }
}

// Fallback detection method
function simulateDetection(url) {
  setTimeout(async () => {
    // Improved detection logic with more sophisticated patterns
    const suspiciousPatterns = [
      'phishing', 'malware', 'verify-account', 'login-verify', 
      'confirm-identity', 'banking-alert', 'account-update',
      'paypal.com-', 'secure-login', 'apple.com.', 'microsoft-verify',
      'amazon-secure', 'facebook.com-login', 'bank-secure'
    ];
    
    // Check for IP addresses in URL
    const hasIPAddress = /^(https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.test(url);
    
    // Check for long subdomains (potential deception)
    const longSubdomain = (url.match(/\./g) || []).length > 3;
    
    // Check for suspicious TLDs
    const suspiciousTLD = /\.(xyz|top|gq|ml|ga|cf|tk|info|work|pro|men|loan|click|date)$/.test(url);
    
    // Check if URL contains suspicious patterns
    const hasSuspiciousPattern = suspiciousPatterns.some(pattern => url.toLowerCase().includes(pattern));
    
    // Calculate threat probability
    let threatProbability = 0;
    if (hasIPAddress) threatProbability += 0.4;
    if (longSubdomain) threatProbability += 0.2;
    if (suspiciousTLD) threatProbability += 0.3;
    if (hasSuspiciousPattern) threatProbability += 0.3;
    
    const isThreat = threatProbability > 0.4 || Math.random() < 0.05; // 5% random chance for demo
    
    if (isThreat) {
      const riskLevel = threatProbability > 0.6 ? "High" : "Medium";
      
      // Create threat details
      const threatDetails = [];
      if (hasIPAddress) threatDetails.push("IP address used instead of domain name");
      if (longSubdomain) threatDetails.push("Excessive number of subdomains");
      if (suspiciousTLD) threatDetails.push("Suspicious top-level domain");
      if (hasSuspiciousPattern) threatDetails.push("URL contains suspicious keywords");
      
      const threatInfo = {
        url: url,
        type: 'Potential Phishing',
        riskLevel: riskLevel,
        timestamp: new Date().toISOString(),
        details: 'This website exhibits characteristics commonly associated with phishing attempts.',
        flaggedElements: threatDetails.length > 0 ? threatDetails : [
          'Suspicious form elements collecting sensitive data',
          'Domain mimicking a legitimate service',
          'Insecure connection'
        ]
      };
      
      // Cache the threat
      chrome.storage.local.get(['threatUrls'], (result) => {
        const threatUrls = result.threatUrls || [];
        // Check if URL already exists in threats
        const existingIndex = threatUrls.findIndex(t => t.url === url);
        
        if (existingIndex >= 0) {
          // Update existing threat
          threatUrls[existingIndex] = threatInfo;
        } else {
          // Add new threat
          threatUrls.push(threatInfo);
        }
        
        chrome.storage.local.set({threatUrls}, async () => {
          updateUIStatus('danger', 'Threat detected on this website!');
          showThreatDetails(threatInfo);
          await updateStats(true);
          
          // Notify background script about the threat
          chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            chrome.runtime.sendMessage({
              action: 'threatDetected',
              tabId: tabs[0].id,
              url: url
            });
          });
        });
      });
    } else {
      // Cache the safe URL
      chrome.storage.local.get(['safeUrls'], (result) => {
        const safeUrls = result.safeUrls || [];
        // Only add if not already in the list
        if (!safeUrls.includes(url)) {
          safeUrls.push(url);
        }
        
        chrome.storage.local.set({safeUrls}, async () => {
          updateUIStatus('safe', 'This website is safe to browse.');
          
          // Clear threat details
          document.getElementById('threatDetailsContainer').innerHTML = '';
          
          await updateStats(false);
          
          // Notify background script about the safe site
          chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            chrome.runtime.sendMessage({
              action: 'safeSiteDetected',
              tabId: tabs[0].id,
              url: url
            });
          });
        });
      });
    }
  }, 1500);
}

function blockCurrentSite() {
  // This would implement blocking functionality in a real extension
  chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    const currentTab = tabs[0];
    // In a real extension, this would redirect to a blocking page
    chrome.tabs.update(currentTab.id, {url: 'blocked.html'});
  });
}

// Show scan history
function showHistory() {
  const content = document.querySelector('.content');
  
  chrome.storage.local.get(['safeUrls', 'threatUrls'], (result) => {
    const safeUrls = result.safeUrls || [];
    const threatUrls = result.threatUrls || [];
    
    // Sort by most recent first (would need timestamps in real implementation)
    const allUrls = [
      ...threatUrls.map(item => ({ 
        url: item.url, 
        type: 'threat', 
        riskLevel: item.riskLevel || 'Unknown', 
        date: new Date().toLocaleDateString() 
      })),
      ...safeUrls.map(url => ({ 
        url: url, 
        type: 'safe', 
        riskLevel: 'None', 
        date: new Date().toLocaleDateString() 
      }))
    ];
    
    content.innerHTML = `
      <div class="history-container">
        <h2>Browsing History</h2>
        
        <div class="history-filters">
          <button class="history-filter active" data-filter="all">All</button>
          <button class="history-filter" data-filter="threat">Threats</button>
          <button class="history-filter" data-filter="safe">Safe</button>
        </div>
        
        <div class="history-list">
          ${allUrls.length > 0 ? 
            allUrls.map(item => `
              <div class="history-item ${item.type}">
                <div class="history-icon">${item.type === 'threat' ? '⛔' : '✅'}</div>
                <div class="history-details">
                  <div class="history-url">${truncateUrl(item.url)}</div>
                  <div class="history-meta">
                    <span class="history-risk">${item.riskLevel}</span>
                    <span class="history-date">${item.date}</span>
                  </div>
                </div>
              </div>
            `).join('') : 
            '<div class="empty-state">No history available</div>'
          }
        </div>
      </div>
    `;
    
    // Add filter functionality
    document.querySelectorAll('.history-filter').forEach(button => {
      button.addEventListener('click', () => {
        // Update active button
        document.querySelectorAll('.history-filter').forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Filter the items
        const filter = button.getAttribute('data-filter');
        document.querySelectorAll('.history-item').forEach(item => {
          if (filter === 'all' || item.classList.contains(filter)) {
            item.style.display = 'flex';
          } else {
            item.style.display = 'none';
          }
        });
      });
    });
  });
}

// Helper function to truncate long URLs
function truncateUrl(url) {
  const maxLength = 40;
  return url.length > maxLength ? url.substring(0, maxLength) + '...' : url;
}

// Password security checker
function showPasswordChecker() {
  const content = document.querySelector('.content');
  
  content.innerHTML = `
    <div class="password-checker">
      <h2>Password Security Checker</h2>
      <p>Check your password strength without sending it to any server.</p>
      
      <div class="password-input-container">
        <input type="password" id="passwordInput" placeholder="Enter your password" class="password-input">
        <button id="togglePassword" class="password-toggle">👁️</button>
      </div>
      
      <div class="password-strength-meter">
        <div id="strengthMeter" class="strength-meter-bar"></div>
      </div>
      
      <div id="strengthResult" class="strength-result">Password strength will appear here</div>
      
      <div id="passwordFeedback" class="password-feedback"></div>
      
      <div class="password-tips">
        <h3>Tips for a strong password:</h3>
        <ul>
          <li>Use at least 12 characters</li>
          <li>Mix uppercase and lowercase letters</li>
          <li>Include numbers and special characters</li>
          <li>Avoid common words and patterns</li>
          <li>Don't reuse passwords across sites</li>
        </ul>
      </div>
    </div>
  `;
  
  // Toggle password visibility
  document.getElementById('togglePassword').addEventListener('click', () => {
    const passwordInput = document.getElementById('passwordInput');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    document.getElementById('togglePassword').textContent = type === 'password' ? '👁️' : '🔒';
  });
  
  // Check password strength on input
  document.getElementById('passwordInput').addEventListener('input', (e) => {
    const password = e.target.value;
    const result = checkPasswordStrength(password);
    
    // Update strength meter
    const strengthMeter = document.getElementById('strengthMeter');
    strengthMeter.style.width = `${result.score * 25}%`;
    strengthMeter.className = 'strength-meter-bar ' + result.strengthLabel.toLowerCase().replace(' ', '-');
    
    // Update result text
    document.getElementById('strengthResult').textContent = `Strength: ${result.strengthLabel}`;
    
    // Update feedback
    document.getElementById('passwordFeedback').innerHTML = result.feedback.length > 0 
      ? `<h3>Suggestions:</h3><ul>${result.feedback.map(item => `<li>${item}</li>`).join('')}</ul>`
      : '';
  });
}

// Function to check password strength
function checkPasswordStrength(password) {
  // Initialize values
  let score = 0;
  const feedback = [];
  
  // Check if password exists
  if (!password) {
    return {
      score: 0,
      strengthLabel: 'None',
      feedback: ['Please enter a password']
    };
  }
  
  // Check length
  if (password.length < 8) {
    feedback.push('Password is too short (minimum 8 characters)');
  } else if (password.length >= 12) {
    score += 1;
  }
  
  // Check for uppercase letters
  if (/[A-Z]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Add uppercase letters');
  }
  
  // Check for lowercase letters
  if (/[a-z]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Add lowercase letters');
  }
  
  // Check for numbers
  if (/[0-9]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Add numbers');
  }
  
  // Check for special characters
  if (/[^A-Za-z0-9]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Add special characters');
  }
  
  // Check for repeated characters
  if (/(.)\1{2,}/.test(password)) {
    score -= 1;
    feedback.push('Avoid repeated characters');
  }
  
  // Check for sequential characters
  if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password)) {
    score -= 1;
    feedback.push('Avoid sequential characters');
  }
  
  // Check for common passwords
  const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome', 'login', 'abc123'];
  if (commonPasswords.includes(password.toLowerCase())) {
    score = 0;
    feedback.push('This is a commonly used password');
  }
  
  // Normalize score (0-4)
  score = Math.max(0, Math.min(4, score));
  
  // Map score to strength label
  const strengthLabels = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'];
  const strengthLabel = strengthLabels[score];
  
  return {
    score,
    strengthLabel,
    feedback
  };
}

// Add or replace toggleThreatDetails function
function toggleThreatDetails() {
  const container = document.getElementById('threatDetailsContainer');
  
  if (container.style.display === 'none' || container.innerHTML === '') {
    chrome.storage.local.get(['threatUrls'], async (result) => {
      const tabs = await chrome.tabs.query({active: true, currentWindow: true});
      const currentUrl = tabs[0].url;
      const threatUrls = result.threatUrls || [];
      const threatInfo = threatUrls.find(threat => threat.url === currentUrl);
      
      if (threatInfo) {
        showThreatDetails(threatInfo);
        container.style.display = 'block';
      } else {
        // If no threat found for current URL, show a message
        container.innerHTML = `
          <div class="threat-details">
            <div class="threat-header">No Threats Detected</div>
            <div class="threat-item">
              <div class="threat-icon">✅</div>
              <div class="threat-text">
                This website appears to be safe. No suspicious elements were detected.
              </div>
            </div>
          </div>
        `;
        container.style.display = 'block';
      }
    });
  } else {
    container.style.display = 'none';
  }
}