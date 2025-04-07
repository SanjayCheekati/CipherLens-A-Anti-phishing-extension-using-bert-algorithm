/**
 * Common utility functions for CipherLens
 */

/**
 * Formats a URL for display by truncating it if it's too long
 * @param {string} url - The URL to format
 * @param {number} maxLength - Maximum length before truncation
 * @returns {string} - Formatted URL
 */
export function formatUrl(url, maxLength = 50) {
  if (!url) return '';
  
  try {
    const urlObj = new URL(url);
    const displayUrl = url.replace(/^https?:\/\//, '');
    
    if (displayUrl.length <= maxLength) {
      return displayUrl;
    }
    
    // If URL is too long, truncate it
    return displayUrl.substring(0, maxLength - 3) + '...';
  } catch (error) {
    // If URL is invalid, just return it as is (truncated if needed)
    return url.length > maxLength ? url.substring(0, maxLength - 3) + '...' : url;
  }
}

/**
 * Sanitizes HTML strings to prevent XSS
 * @param {string} html - The HTML string to sanitize
 * @returns {string} - Sanitized HTML
 */
export function sanitizeHtml(html) {
  if (!html) return '';
  
  const tempElement = document.createElement('div');
  tempElement.textContent = html;
  return tempElement.innerHTML;
}

/**
 * Gets a color based on risk level
 * @param {string} riskLevel - Risk level (Low, Medium, High)
 * @returns {string} - CSS color value
 */
export function getRiskColor(riskLevel) {
  switch (riskLevel?.toLowerCase()) {
    case 'low':
      return '#4caf50'; // Green
    case 'medium':
      return '#ff9800'; // Orange
    case 'high':
      return '#f44336'; // Red
    default:
      return '#2196f3'; // Blue (default)
  }
}

/**
 * Debounces a function to prevent rapid repeated calls
 * @param {Function} func - The function to debounce
 * @param {number} wait - The time to wait in milliseconds
 * @returns {Function} - Debounced function
 */
export function debounce(func, wait = 300) {
  let timeout;
  
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Creates a unique ID
 * @returns {string} - Unique ID
 */
export function createUniqueId() {
  return `id_${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Formats a date in a user-friendly way
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date
 */
export function formatDate(dateString) {
  if (!dateString) return '';
  
  try {
    const date = new Date(dateString);
    return date.toLocaleString();
  } catch (error) {
    return dateString;
  }
}

/**
 * Gets domain name from a URL
 * @param {string} url - The URL
 * @returns {string} - Domain name
 */
export function getDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (error) {
    return url;
  }
}

/**
 * Checks if a URL is internal (browser page)
 * @param {string} url - URL to check
 * @returns {boolean} - True if internal
 */
export function isInternalUrl(url) {
  return url.startsWith('chrome://') || 
         url.startsWith('edge://') || 
         url.startsWith('about:') || 
         url.startsWith('file://');
}

/**
 * Logs an event to the console (with filtering for production)
 * @param {string} type - Event type
 * @param {any} data - Event data
 */
export function logEvent(type, data) {
  // In production, we would limit logging or send to a monitoring service
  const isDev = process.env.NODE_ENV === 'development';
  
  if (isDev) {
    console.log(`[${type}]`, data);
  }
} 