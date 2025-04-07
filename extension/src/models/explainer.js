/**
 * Explainer - A simplified model for explaining threat detections
 * 
 * In a real extension, this would be a SHAP or LIME-based explainer
 * For demonstration purposes, this uses simplified feature attribution
 */

class Explainer {
  constructor() {
    this.initialized = false;
    
    // Map feature names to user-friendly descriptions
    this.featureDescriptions = {
      hasIPAddress: 'Use of IP address in URL',
      urlLength: 'Unusually long URL',
      hasAtSymbol: 'URL contains @ symbol',
      hasManySubdomains: 'Multiple subdomains',
      hasSuspiciousTLD: 'Suspicious top-level domain',
      hasHyphens: 'Multiple hyphens in domain',
      hasPasswordField: 'Password input field',
      hasSensitiveKeywords: 'Sensitive keywords',
      mismatchedFormAction: 'Form submits to different domain',
      isNotHttps: 'Non-secure connection',
      hasCertificateIssues: 'SSL certificate issues'
    };
  }
  
  async initialize() {
    // In a real extension, this would load the SHAP/LIME model
    // For demo purposes, just simulate loading delay
    await new Promise(resolve => setTimeout(resolve, 300));
    this.initialized = true;
    return true;
  }
  
  /**
   * Generate explanations for a phishing prediction
   * @param {Object} features - Extracted features
   * @param {Object} weights - Feature weights from the model
   * @returns {Array} - Array of explanation objects
   */
  async explainPrediction(features, weights) {
    if (!this.initialized) {
      await this.initialize();
    }
    
    // Calculate feature attributions (in a real system, this would be SHAP/LIME values)
    const attributions = {};
    let totalAttribution = 0;
    
    for (const [feature, value] of Object.entries(features)) {
      if (value > 0) {
        const weight = weights[feature] || 0;
        attributions[feature] = value * weight;
        totalAttribution += attributions[feature];
      }
    }
    
    // Normalize attributions to percentages
    const normalizedAttributions = {};
    for (const [feature, attribution] of Object.entries(attributions)) {
      normalizedAttributions[feature] = totalAttribution > 0 ? 
        (attribution / totalAttribution * 100).toFixed(1) : 0;
    }
    
    // Convert to array and sort by attribution value (descending)
    const sortedExplanations = Object.entries(normalizedAttributions)
      .map(([feature, attribution]) => ({
        feature,
        description: this.featureDescriptions[feature] || feature,
        attribution: parseFloat(attribution),
        value: features[feature]
      }))
      .filter(item => item.attribution > 0)
      .sort((a, b) => b.attribution - a.attribution);
    
    return sortedExplanations;
  }
  
  /**
   * Generate HTML to visualize feature contributions
   * @param {Array} explanations - Array of explanation objects
   * @returns {string} - HTML string for visualization
   */
  generateVisualization(explanations) {
    if (!explanations || explanations.length === 0) {
      return '<div class="empty-explanation">No significant factors found.</div>';
    }
    
    // Create HTML for visualization
    let html = '<div class="explanation-container">';
    
    explanations.forEach(exp => {
      const barWidth = Math.max(5, exp.attribution); // Minimum 5% width for visibility
      
      html += `
        <div class="explanation-item">
          <div class="explanation-label">${exp.description}</div>
          <div class="explanation-bar-container">
            <div class="explanation-bar" style="width: ${barWidth}%"></div>
            <div class="explanation-value">${exp.attribution}%</div>
          </div>
        </div>
      `;
    });
    
    html += '</div>';
    return html;
  }
  
  /**
   * Extract suspicious elements from the DOM based on feature attributions
   * @param {Document} document - The webpage document
   * @param {Array} explanations - Array of explanation objects
   * @returns {Array} - Array of suspicious elements with descriptions
   */
  identifySuspiciousElements(document, explanations) {
    const suspiciousElements = [];
    
    // Look for suspicious elements based on top explanations
    explanations.forEach(exp => {
      switch(exp.feature) {
        case 'hasPasswordField':
          const passwordFields = document.querySelectorAll('input[type="password"]');
          passwordFields.forEach(field => {
            suspiciousElements.push({
              element: 'Password input field',
              description: 'Sensitive data collection',
              selector: this._getSelector(field)
            });
          });
          break;
          
        case 'mismatchedFormAction':
          const forms = document.querySelectorAll('form');
          forms.forEach(form => {
            if (form.action && !form.action.includes(document.location.hostname)) {
              suspiciousElements.push({
                element: 'Form',
                description: `Submits data to external domain: ${form.action}`,
                selector: this._getSelector(form)
              });
            }
          });
          break;
          
        case 'hasSensitiveKeywords':
          // Look for login forms and sensitive content
          const loginForms = document.querySelectorAll('form:has(input[type="password"])');
          loginForms.forEach(form => {
            suspiciousElements.push({
              element: 'Login form',
              description: 'Collecting sensitive credentials',
              selector: this._getSelector(form)
            });
          });
          break;
      }
    });
    
    return suspiciousElements;
  }
  
  /**
   * Generate a CSS selector for an element (simplified)
   * @param {Element} element - DOM element
   * @returns {string} - CSS selector
   */
  _getSelector(element) {
    // This is a simplified version - a real implementation would be more robust
    if (element.id) {
      return `#${element.id}`;
    }
    
    if (element.className) {
      const classes = element.className.split(' ').filter(c => c.trim().length > 0);
      if (classes.length > 0) {
        return `.${classes.join('.')}`;
      }
    }
    
    // Fallback to element type
    return element.tagName.toLowerCase();
  }
}

export default Explainer; 