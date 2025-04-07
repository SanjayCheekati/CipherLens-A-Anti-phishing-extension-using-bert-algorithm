import React from 'react';

/**
 * StatusBar component displays the current security status of the webpage
 */
const StatusBar = ({ status, message }) => {
  // Map status to icon and class
  const getStatusInfo = () => {
    switch(status) {
      case 'safe':
        return {
          icon: '✅',
          className: 'status safe',
          title: 'Safe'
        };
      case 'danger':
        return {
          icon: '⚠️',
          className: 'status danger',
          title: 'Danger'
        };
      case 'warning':
        return {
          icon: '🔍',
          className: 'status warning',
          title: 'Warning'
        };
      default:
        return {
          icon: '🔍',
          className: 'status',
          title: 'Analyzing'
        };
    }
  };
  
  const statusInfo = getStatusInfo();
  
  return (
    <div className={statusInfo.className} title={statusInfo.title}>
      <span className="status-icon">{statusInfo.icon}</span>
      <span className="status-text">{message || statusInfo.title}</span>
    </div>
  );
};

export default StatusBar; 