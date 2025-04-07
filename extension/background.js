// Background script for CipherLens extension

// Initialize stats when extension is installed
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['safeUrls', 'threatUrls', 'scanCount', 'darkTheme'], (result) => {
    if (!result.safeUrls) {
      chrome.storage.local.set({ safeUrls: [] });
    }
    if (!result.threatUrls) {
      chrome.storage.local.set({ threatUrls: [] });
    }
    if (!result.scanCount) {
      chrome.storage.local.set({ scanCount: 0 });
    }
    if (result.darkTheme === undefined) {
      chrome.storage.local.set({ darkTheme: false });
    }
  });
  
  // Set default icon
  chrome.action.setIcon({
    path: {
      16: "assets/icon16.png",
      48: "assets/icon48.png",
      128: "assets/icon128.png"
    }
  });
});

// Listen for tab updates to scan new pages
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only act if the page has completed loading
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    // Check if URL is in safe or threat lists
    chrome.storage.local.get(['safeUrls', 'threatUrls'], (result) => {
      const safeUrls = result.safeUrls || [];
      const threatUrls = result.threatUrls || [];
      
      // Check if this URL is in our safe list
      if (safeUrls.includes(tab.url)) {
        // Set safe icon
        chrome.action.setIcon({
          path: {
            16: "assets/icon-safe.png",
            48: "assets/icon-safe.png",
            128: "assets/icon-safe.png"
          },
          tabId: tabId
        });
      } 
      // Check if this URL is in our threat list
      else if (threatUrls.some(threat => threat.url === tab.url)) {
        // Set default/warning icon
        chrome.action.setIcon({
          path: {
            16: "assets/icon-danger.png",
            48: "assets/icon-danger.png",
            128: "assets/icon-danger.png"
          },
          tabId: tabId
        });
        
        // Automatically open the popup to alert the user
        chrome.action.openPopup();
      }
      // Otherwise, just set default icon
      else {
        chrome.action.setIcon({
          path: {
            16: "assets/icon16.png",
            48: "assets/icon48.png",
            128: "assets/icon128.png"
          },
          tabId: tabId
        });
      }
    });
  }
});

// Listen for web navigation to detect when a new page is loaded
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only process main frame (not iframes or other sub-resources)
  if (details.frameId === 0) {
    const url = details.url;
    
    // Skip browser internal pages and local files
    if (url.startsWith('chrome://') || url.startsWith('file://')) {
      return;
    }
    
    // Check if URL is already in cache
    const cache = await chrome.storage.local.get(['safeUrls', 'threatUrls']);
    const safeUrls = cache.safeUrls || [];
    const threatUrls = cache.threatUrls || [];
    
    if (safeUrls.includes(url)) {
      updateIcon('safe', details.tabId);
    } else if (threatUrls.some(threat => threat.url === url)) {
      updateIcon('danger', details.tabId);
      showNotification(url);
    } else {
      // URL not in cache, analyze it
      updateIcon('warning', details.tabId); // Set to scanning state
      analyzeWebsite(url, details.tabId);
    }
  }
});

// Function to update the extension icon based on status
function updateIcon(status, tabId) {
  let iconPath = {
    16: "assets/icon16.png",
    48: "assets/icon48.png",
    128: "assets/icon128.png"
  };
  
  switch(status) {
    case 'safe':
      iconPath = {
        16: "assets/icon-safe.png",
        48: "assets/icon-safe.png",
        128: "assets/icon-safe.png"
      };
      break;
    case 'danger':
      iconPath = {
        16: "assets/icon-danger.png",
        48: "assets/icon-danger.png",
        128: "assets/icon-danger.png"
      };
      break;
    case 'warning':
      iconPath = {
        16: "assets/icon-warning.png",
        48: "assets/icon-warning.png",
        128: "assets/icon-warning.png"
      };
      break;
  }
  
  if (tabId) {
    chrome.action.setIcon({ path: iconPath, tabId });
  } else {
    chrome.action.setIcon({ path: iconPath });
  }
}

// Function to analyze a website
async function analyzeWebsite(url, tabId) {
  try {
    // In a real extension, this would call your ML model or backend service
    // For demo purposes, we'll simulate an API call with a timeout
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Get the page content via content script
    chrome.tabs.sendMessage(tabId, { action: 'getPageContent' }, async (response) => {
      if (chrome.runtime.lastError) {
        // Content script may not be ready yet, inject it
        await chrome.tabs.executeScript(tabId, { file: 'contentScript.js' });
        // Try again after a short delay
        setTimeout(() => analyzeWebsite(url, tabId), 500);
        return;
      }
      
      // Simple demo detection logic - in reality, this would use your ML model
      const isThreat = url.includes('phishing') || 
                       url.includes('malware') || 
                       response?.content?.includes('password') ||
                       Math.random() < 0.1; // 10% chance for demo purposes
      
      if (isThreat) {
        // Create threat info object
        const threatInfo = {
          url: url,
          type: 'Potential Phishing',
          riskLevel: 'High',
          details: 'This website exhibits characteristics commonly associated with phishing attempts.',
          flaggedElements: [
            'Suspicious form elements collecting sensitive data',
            'Domain mimicking a legitimate service',
            'Insecure connection'
          ],
          timestamp: new Date().toISOString()
        };
        
        // Update cache
        chrome.storage.local.get(['threatUrls'], (result) => {
          const threatUrls = result.threatUrls || [];
          threatUrls.push(threatInfo);
          chrome.storage.local.set({ threatUrls });
        });
        
        updateIcon('danger', tabId);
        showNotification(url);
      } else {
        // URL is safe, add to cache
        chrome.storage.local.get(['safeUrls'], (result) => {
          const safeUrls = result.safeUrls || [];
          if (!safeUrls.includes(url)) {
            safeUrls.push(url);
            chrome.storage.local.set({ safeUrls });
          }
        });
        
        updateIcon('safe', tabId);
      }
    });
  } catch (error) {
    console.error('Error analyzing website:', error);
    updateIcon('warning', tabId);
  }
}

// Function to show notifications
function showNotification(url) {
  chrome.storage.local.get(['notificationLevel'], (result) => {
    const level = result.notificationLevel || 'all';
    
    if (level === 'none') return;
    
    // For 'high' level, we could check the threat risk level here
    // but for demo purposes we'll show all notifications
    
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'assets/icon-danger.png',
      title: 'CipherLens Security Alert',
      message: `Potential threat detected on: ${url.substring(0, 50)}...`,
      priority: 2
    });
  });
}

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'threatDetected') {
    // Threat was detected, open the popup
    chrome.action.openPopup();
    sendResponse({ success: true });
    return true;
  }
  if (message.action === 'safeSiteDetected') {
    // Safe site detected, update the icon
    chrome.action.setIcon({
      path: {
        16: "assets/icon-safe.png",
        48: "assets/icon-safe.png",
        128: "assets/icon-safe.png"
      },
      tabId: message.tabId
    });
    sendResponse({ success: true });
    return true;
  }
}); 