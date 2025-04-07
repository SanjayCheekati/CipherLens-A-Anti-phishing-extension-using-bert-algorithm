/**
 * PhishingDetector - A simplified model for phishing detection
 * 
 * In a real extension, this would be a BERT-based model loaded with TensorFlow.js
 * For demonstration purposes, this uses rule-based heuristics instead
 */

class PhishingDetector {
  constructor() {
    this.initialized = false;
    this.featureWeights = {
      // URL-based features
      hasIPAddress: 0.8,
      urlLength: 0.3,
      hasAtSymbol: 0.7,
      hasManySubdomains: 0.6,
      hasSuspiciousTLD: 0.7,
      hasHyphens: 0.4,
      
      // Content-based features
      hasPasswordField: 0.8,
      hasSensitiveKeywords: 0.6,
      mismatchedFormAction: 0.9,
      
      // Security indicators
      isNotHttps: 0.8,
      hasCertificateIssues: 0.9
    };
    
    this.suspiciousTLDs = [
      '.xyz', '.top', '.gq', '.ml', '.ga', '.cf', '.tk'
    ];
  }
  
  async initialize() {
    // In a real extension, this would load the model weights
    // For demo, just simulate a delay
    await new Promise(resolve => setTimeout(resolve, 500));
    this.initialized = true;
    return true;
  }
  
  /**
   * Extract features from the URL and page content
   * @param {string} url - The URL to analyze
   * @param {Object} pageFeatures - Features extracted from the page
   * @returns {Object} - Extracted features
   */
  extractFeatures(url, pageFeatures) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      
      const features = {
        // URL-based features
        hasIPAddress: this._hasIPAddress(domain),
        urlLength: url.length > 75 ? 1 : (url.length > 50 ? 0.5 : 0),
        hasAtSymbol: url.includes('@') ? 1 : 0,
        hasManySubdomains: domain.split('.').length > 3 ? 1 : 0,
        hasSuspiciousTLD: this._hasSuspiciousTLD(domain) ? 1 : 0,
        hasHyphens: domain.includes('-') ? (domain.split('-').length > 2 ? 1 : 0.5) : 0,
        
        // Content-based features from pageFeatures
        hasPasswordField: pageFeatures.hasPasswordField ? 1 : 0,
        hasSensitiveKeywords: pageFeatures.hasSensitiveKeywords ? 1 : 0,
        mismatchedFormAction: this._hasFormActionMismatch(url, pageFeatures.formAction) ? 1 : 0,
        
        // Security indicators
        isNotHttps: url.startsWith('https://') ? 0 : 1,
        hasCertificateIssues: pageFeatures.securityIndicators?.hasCertificateIssues ? 1 : 0
      };
      
      return features;
    } catch (error) {
      console.error('Error extracting features:', error);
      return {};
    }
  }
  
  /**
   * Predict if a URL is a phishing attempt
   * @param {string} url - The URL to analyze
   * @param {Object} pageFeatures - Features extracted from the page
   * @returns {Object} - Prediction result with score and explanation
   */
  async predict(url, pageFeatures) {
    if (!this.initialized) {
      await this.initialize();
    }
    
    const features = this.extractFeatures(url, pageFeatures);
    
    // Calculate phishing score as weighted sum of features
    let score = 0;
    let totalWeight = 0;
    const featureContributions = {};
    
    for (const [feature, value] of Object.entries(features)) {
      const weight = this.featureWeights[feature] || 0;
      score += value * weight;
      totalWeight += weight;
      
      // Store feature contributions for explanation
      featureContributions[feature] = value * weight;
    }
    
    // Normalize score between 0 and 1
    score = totalWeight > 0 ? score / totalWeight : 0;
    
    // Get top contributing features for explanation
    const contributingFeatures = Object.entries(featureContributions)
      .filter(([_, contribution]) => contribution > 0)
      .sort(([_, a], [__, b]) => b - a)
      .slice(0, 3)
      .map(([feature, _]) => this._getFeatureExplanation(feature));
    
    return {
      isPhishing: score > 0.6, // Threshold for classification
      score: score,
      confidence: Math.min(Math.abs(score - 0.5) * 2, 0.99), // Convert to confidence
      explanations: contributingFeatures,
      threatLevel: this._getThreatLevel(score)
    };
  }
  
  /**
   * Get human-readable explanation for a feature
   * @param {string} feature - Feature name
   * @returns {string} - Human-readable explanation
   */
  _getFeatureExplanation(feature) {
    const explanations = {
      hasIPAddress: 'Website uses an IP address instead of a domain name',
      urlLength: 'Unusually long URL',
      hasAtSymbol: 'URL contains @ symbol',
      hasManySubdomains: 'URL has an excessive number of subdomains',
      hasSuspiciousTLD: 'Website uses a suspicious top-level domain',
      hasHyphens: 'Domain contains multiple hyphens',
      hasPasswordField: 'Page contains password input fields',
      hasSensitiveKeywords: 'Page contains sensitive keywords related to login/payment',
      mismatchedFormAction: 'Form submission URL different from current domain',
      isNotHttps: 'Website does not use secure HTTPS connection',
      hasCertificateIssues: 'Website has SSL certificate issues'
    };
    
    return explanations[feature] || feature;
  }
  
  /**
   * Check if a domain is an IP address
   * @param {string} domain - Domain to check
   * @returns {boolean} - True if domain is an IP address
   */
  _hasIPAddress(domain) {
    // Simple regex to detect IP addresses
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    return ipPattern.test(domain);
  }
  
  /**
   * Check if a domain has a suspicious TLD
   * @param {string} domain - Domain to check
   * @returns {boolean} - True if domain has a suspicious TLD
   */
  _hasSuspiciousTLD(domain) {
    return this.suspiciousTLDs.some(tld => domain.endsWith(tld));
  }
  
  /**
   * Check if form action URL is different from current URL domain
   * @param {string} currentUrl - Current page URL
   * @param {string} formAction - Form action URL
   * @returns {boolean} - True if there's a mismatch
   */
  _hasFormActionMismatch(currentUrl, formAction) {
    if (!formAction) return false;
    
    try {
      const currentDomain = new URL(currentUrl).hostname;
      const actionDomain = new URL(formAction, currentUrl).hostname;
      
      return currentDomain !== actionDomain;
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Get threat level based on phishing score
   * @param {number} score - Phishing score
   * @returns {string} - Threat level (Low, Medium, High)
   */
  _getThreatLevel(score) {
    if (score < 0.4) return 'Low';
    if (score < 0.7) return 'Medium';
    return 'High';
  }
}

// Export the detector
export default PhishingDetector; 