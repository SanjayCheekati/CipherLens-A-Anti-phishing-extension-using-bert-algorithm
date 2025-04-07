import React, { useState } from 'react';
import { formatUrl, getRiskColor, formatDate } from '../utils/common';

/**
 * ThreatDetails component displays detailed information about detected threats
 */
const ThreatDetails = ({ threatInfo }) => {
  const [expanded, setExpanded] = useState(false);
  
  if (!threatInfo) {
    return (
      <div className="no-threats">
        <p>No threat information available.</p>
      </div>
    );
  }
  
  const toggleExpanded = () => {
    setExpanded(!expanded);
  };
  
  return (
    <div className="threat-details">
      <div className="threat-header">
        <h3>Threat Information</h3>
        <span 
          className="expand-icon" 
          onClick={toggleExpanded}
        >
          {expanded ? '▼' : '▶'}
        </span>
      </div>
      
      <div className="threat-summary">
        <div className="threat-item">
          <strong>Type:</strong> {threatInfo.type || 'Unknown'}
        </div>
        
        <div className="threat-item">
          <strong>Risk Level:</strong> 
          <span style={{ color: getRiskColor(threatInfo.riskLevel) }}>
            {threatInfo.riskLevel || 'Unknown'}
          </span>
        </div>
        
        <div className="threat-item">
          <strong>URL:</strong> {formatUrl(threatInfo.url, 40)}
        </div>
        
        {threatInfo.timestamp && (
          <div className="threat-item">
            <strong>Detected:</strong> {formatDate(threatInfo.timestamp)}
          </div>
        )}
      </div>
      
      {expanded && (
        <div className="threat-expanded">
          <div className="threat-section">
            <h4>Details</h4>
            <p>{threatInfo.details || 'No additional details available.'}</p>
          </div>
          
          {threatInfo.explanations && threatInfo.explanations.length > 0 && (
            <div className="threat-section">
              <h4>Why this was flagged</h4>
              <ul className="explanation-list">
                {threatInfo.explanations.map((explanation, index) => (
                  <li key={index}>{explanation}</li>
                ))}
              </ul>
            </div>
          )}
          
          {threatInfo.flaggedElements && threatInfo.flaggedElements.length > 0 && (
            <div className="threat-section">
              <h4>Flagged Elements</h4>
              <ul className="flagged-elements-list">
                {threatInfo.flaggedElements.map((element, index) => (
                  <li key={index}>{element}</li>
                ))}
              </ul>
            </div>
          )}
          
          <div className="threat-actions">
            <button className="action-button block">Block Site</button>
            <button className="action-button report">Report False Positive</button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatDetails; 