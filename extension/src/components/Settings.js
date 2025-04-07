import React, { useState, useEffect } from 'react';

/**
 * Settings component for user preferences and configuration
 */
const Settings = ({ onClose }) => {
  const [darkTheme, setDarkTheme] = useState(false);
  const [notificationLevel, setNotificationLevel] = useState('all');
  const [scanningMode, setScanningMode] = useState('standard');
  const [clearHistory, setClearHistory] = useState(false);
  
  useEffect(() => {
    // Load settings from storage when component mounts
    const loadSettings = async () => {
      try {
        const result = await chrome.storage.local.get([
          'darkTheme',
          'notificationLevel',
          'scanningMode'
        ]);
        
        setDarkTheme(result.darkTheme || false);
        setNotificationLevel(result.notificationLevel || 'all');
        setScanningMode(result.scanningMode || 'standard');
      } catch (error) {
        console.error('Error loading settings:', error);
      }
    };
    
    loadSettings();
  }, []);
  
  const saveSettings = async () => {
    try {
      await chrome.storage.local.set({
        darkTheme,
        notificationLevel,
        scanningMode
      });
      
      // Apply theme immediately
      if (darkTheme) {
        document.body.classList.add('dark-theme');
      } else {
        document.body.classList.remove('dark-theme');
      }
      
      // Clear history if requested
      if (clearHistory) {
        await chrome.storage.local.set({
          safeUrls: [],
          threatUrls: []
        });
        setClearHistory(false);
      }
      
      // Notify background script about settings change
      chrome.runtime.sendMessage({ action: 'settingsUpdated' });
      
      // Close settings panel
      onClose();
    } catch (error) {
      console.error('Error saving settings:', error);
    }
  };
  
  return (
    <div className="settings-panel">
      <div className="settings-header">
        <h3>Settings</h3>
        <span className="close-icon" onClick={onClose}>×</span>
      </div>
      
      <div className="settings-content">
        {/* Theme Setting */}
        <div className="setting-item">
          <span className="setting-label">Dark Theme</span>
          <label className="switch">
            <input 
              type="checkbox" 
              checked={darkTheme}
              onChange={(e) => setDarkTheme(e.target.checked)}
            />
            <span className="slider"></span>
          </label>
        </div>
        
        {/* Notification Setting */}
        <div className="setting-item">
          <span className="setting-label">Notification Level</span>
          <select 
            value={notificationLevel}
            onChange={(e) => setNotificationLevel(e.target.value)}
          >
            <option value="all">All Threats</option>
            <option value="high">High Risk Only</option>
            <option value="none">None</option>
          </select>
        </div>
        
        {/* Scanning Mode */}
        <div className="setting-item">
          <span className="setting-label">Scanning Mode</span>
          <select 
            value={scanningMode}
            onChange={(e) => setScanningMode(e.target.value)}
          >
            <option value="standard">Standard (Recommended)</option>
            <option value="aggressive">Aggressive</option>
            <option value="minimal">Minimal</option>
          </select>
          <div className="setting-description">
            {scanningMode === 'aggressive' && 
              'Aggressive mode may impact browsing performance but provides maximum security.'}
            {scanningMode === 'minimal' && 
              'Minimal mode only checks for critical threats.'}
            {scanningMode === 'standard' && 
              'Balanced security and performance.'}
          </div>
        </div>
        
        {/* Clear History */}
        <div className="setting-item">
          <span className="setting-label">Clear Browsing History</span>
          <label className="switch">
            <input 
              type="checkbox" 
              checked={clearHistory}
              onChange={(e) => setClearHistory(e.target.checked)}
            />
            <span className="slider"></span>
          </label>
          <div className="setting-description">
            Clear all cached safe/threat URLs
          </div>
        </div>
      </div>
      
      <div className="settings-footer">
        <button 
          className="settings-button cancel"
          onClick={onClose}
        >
          Cancel
        </button>
        <button 
          className="settings-button save"
          onClick={saveSettings}
        >
          Save
        </button>
      </div>
    </div>
  );
};

export default Settings; 