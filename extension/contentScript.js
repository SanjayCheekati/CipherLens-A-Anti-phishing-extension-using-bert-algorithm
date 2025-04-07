// Content script for CipherLens
// This script is injected into every webpage the user visits

// Store features extracted from the current page
const extractedFeatures = {
  url: window.location.href,
  domain: window.location.hostname,
  hasPasswordField: false,
  hasSensitiveKeywords: false,
  externalLinks: [],
  formAction: null,
  securityIndicators: {
    isHttps: window.location.protocol === 'https:',
    hasCertificateIssues: false // Would require backend check in a real extension
  }
};

// Function to extract features from the current webpage
function extractPageFeatures() {
  // Check for password fields
  const passwordFields = document.querySelectorAll('input[type="password"]');
  extractedFeatures.hasPasswordField = passwordFields.length > 0;
  
  // Look for forms and their submission URLs
  const forms = document.querySelectorAll('form');
  if (forms.length > 0) {
    const form = forms[0]; // Just examine the first form for demo purposes
    extractedFeatures.formAction = form.action || null;
  }
  
  // Extract external links
  const links = document.querySelectorAll('a');
  links.forEach(link => {
    try {
      const href = link.href;
      if (href && !href.startsWith(window.location.origin) && 
          !href.startsWith('javascript:') && !href.startsWith('#')) {
        extractedFeatures.externalLinks.push(href);
      }
    } catch (e) {
      // Skip malformed URLs
    }
  });
  
  // Check for sensitive keywords in the page content
  const sensitiveKeywords = [
    'password', 'credit card', 'login', 'signin', 'bank', 'account',
    'social security', 'ssn', 'credentials', 'verification', 'authorize',
    'secure', 'update your account'
  ];
  
  const pageText = document.body.innerText.toLowerCase();
  extractedFeatures.hasSensitiveKeywords = sensitiveKeywords.some(keyword => 
    pageText.includes(keyword.toLowerCase())
  );
  
  return extractedFeatures;
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'scanPage') {
    // Scan the page content for suspicious elements
    const pageContent = document.documentElement.outerHTML;
    const pageUrl = window.location.href;
    
    // Extract forms for analysis
    const forms = Array.from(document.forms).map(form => {
      return {
        action: form.action,
        method: form.method,
        hasPasswordField: form.querySelector('input[type="password"]') !== null,
        inputCount: form.querySelectorAll('input').length,
        hasExternalAction: form.action && !form.action.includes(window.location.hostname)
      };
    });
    
    // Check for external scripts
    const scripts = Array.from(document.scripts).map(script => {
      return {
        src: script.src,
        isExternal: script.src && !script.src.includes(window.location.hostname)
      };
    });
    
    // Count suspicious keywords in page text
    const bodyText = document.body.innerText.toLowerCase();
    const suspiciousKeywords = [
      'password', 'credit card', 'update account', 'verify', 'login',
      'secure', 'urgent', 'suspicious activity', 'limited time'
    ];
    
    const keywordMatches = suspiciousKeywords.filter(keyword => 
      bodyText.includes(keyword.toLowerCase())
    );
    
    // Send results back to the extension
    sendResponse({
      url: pageUrl,
      forms: forms,
      scripts: scripts,
      suspiciousKeywords: keywordMatches,
      hasPasswordField: document.querySelector('input[type="password"]') !== null,
      hasIframe: document.querySelectorAll('iframe').length > 0,
      hasObfuscatedCode: document.querySelectorAll('script:not([src])').length > 0
    });
    
    return true; // Indicates async response
  }
  
  if (message.action === 'highlightElement') {
    // Highlight suspicious elements
    const selector = message.selector;
    const elements = document.querySelectorAll(selector);
    
    elements.forEach(el => {
      const originalStyles = {
        outline: el.style.outline,
        boxShadow: el.style.boxShadow,
        position: el.style.position
      };
      
      // Store original styles
      el.dataset.originalStyles = JSON.stringify(originalStyles);
      
      // Apply highlight styles
      el.style.outline = '2px solid #f44336';
      el.style.boxShadow = '0 0 8px #f44336';
      el.style.position = 'relative';
    });
    
    // Send response with count of highlighted elements
    sendResponse({ count: elements.length });
    return true;
  }
  
  if (message.action === 'removeHighlights') {
    // Remove all highlights
    document.querySelectorAll('[data-original-styles]').forEach(el => {
      const originalStyles = JSON.parse(el.dataset.originalStyles);
      
      // Restore original styles
      Object.keys(originalStyles).forEach(key => {
        el.style[key] = originalStyles[key];
      });
      
      // Remove data attribute
      delete el.dataset.originalStyles;
    });
    
    sendResponse({ success: true });
    return true;
  }
});

// Function to highlight suspicious elements (for demonstration purposes)
function highlightSuspiciousElements() {
  // In a real extension, this would use the SHAP/LIME explanations to highlight elements
  // For demo, we'll highlight password fields and external links
  
  const passwordFields = document.querySelectorAll('input[type="password"]');
  passwordFields.forEach(field => {
    field.style.border = '2px solid #f44336';
    
    // Add tooltip
    const tooltip = document.createElement('div');
    tooltip.innerText = 'Sensitive field detected by CipherLens';
    tooltip.style.position = 'absolute';
    tooltip.style.backgroundColor = '#f44336';
    tooltip.style.color = 'white';
    tooltip.style.padding = '5px';
    tooltip.style.borderRadius = '3px';
    tooltip.style.fontSize = '12px';
    tooltip.style.zIndex = '10000';
    tooltip.style.display = 'none';
    
    field.parentNode.insertBefore(tooltip, field.nextSibling);
    
    field.addEventListener('mouseover', () => {
      const rect = field.getBoundingClientRect();
      tooltip.style.left = `${rect.left}px`;
      tooltip.style.top = `${rect.bottom + 5}px`;
      tooltip.style.display = 'block';
    });
    
    field.addEventListener('mouseout', () => {
      tooltip.style.display = 'none';
    });
  });
  
  // Highlight external links that might be suspicious
  const links = document.querySelectorAll('a');
  links.forEach(link => {
    try {
      const href = link.href.toLowerCase();
      const isSuspicious = 
        href.includes('login') ||
        href.includes('signin') ||
        href.includes('account') ||
        href.includes('password') ||
        href.includes('verify');
        
      if (isSuspicious && !href.startsWith(window.location.origin)) {
        link.style.border = '1px dashed #ff9800';
        link.style.padding = '2px';
        link.title = 'CipherLens: Potentially suspicious external link';
      }
    } catch (e) {
      // Skip malformed URLs
    }
  });
}

// Run feature extraction when the page loads
document.addEventListener('DOMContentLoaded', () => {
  extractPageFeatures();
  
  // For demo purposes, we'll highlight suspicious elements on some pages
  // In a real extension, this would only happen on suspicious pages
  if (Math.random() < 0.3) { // 30% chance for demo
    highlightSuspiciousElements();
  }
}); 