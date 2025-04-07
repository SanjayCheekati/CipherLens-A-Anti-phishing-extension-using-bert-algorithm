import React from 'react';
import ReactDOM from 'react-dom';
import ThreatDetails from './components/ThreatDetails';
import Settings from './components/Settings';
import StatusBar from './components/StatusBar';

// Main Popup App component
const Popup = () => {
  const [status, setStatus] = React.useState('warning');
  const [message, setMessage] = React.useState('Analyzing website...');
  const [threatInfo, setThreatInfo] = React.useState(null);
  const [showSettings, setShowSettings] = React.useState(false);
  
  React.useEffect(() => {
    // Get current tab URL
    chrome.tabs.query({active: true, currentWindow: true}, async (tabs) => {
      const currentUrl = tabs[0].url;
      
      // Check if the URL is in the safe/threat cache
      chrome.storage.local.get(['safeUrls', 'threatUrls'], (result) => {
        const safeUrls = result.safeUrls || [];
        const threatUrls = result.threatUrls || [];
        
        if (safeUrls.includes(currentUrl)) {
          setStatus('safe');
          setMessage('This website is safe to browse.');
        } else if (threatUrls.some(threat => threat.url === currentUrl)) {
          const threatInfo = threatUrls.find(threat => threat.url === currentUrl);
          setStatus('danger');
          setMessage('Threat detected on this website.');
          setThreatInfo(threatInfo);
        } else {
          // If not in cache, scan the website
          setStatus('warning');
          setMessage('Scanning website...');
          scanWebsite(currentUrl);
        }
      });
    });
    
    // Check for saved theme preference
    chrome.storage.local.get(['darkTheme'], (result) => {
      if (result.darkTheme) {
        document.body.classList.add('dark-theme');
      }
    });
  }, []);
  
  const scanWebsite = (url) => {
    // In a real extension, this would call the ML model or backend API
    // For demo, simulate a call with a timeout
    setTimeout(() => {
      // Simulate detection logic
      const isThreat = url.includes('phishing') || 
                      url.includes('malware') || 
                      Math.random() < 0.1; // 10% chance for demo
      
      if (isThreat) {
        const threatInfo = {
          url: url,
          type: 'Potential Phishing',
          riskLevel: 'High',
          details: 'This website exhibits characteristics commonly associated with phishing attempts.',
          flaggedElements: [
            'Suspicious form elements collecting sensitive data',
            'Domain mimicking a legitimate service',
            'Insecure connection'
          ]
        };
        
        // Cache the threat
        chrome.storage.local.get(['threatUrls'], (result) => {
          const threatUrls = result.threatUrls || [];
          threatUrls.push(threatInfo);
          chrome.storage.local.set({threatUrls}, () => {
            setStatus('danger');
            setMessage('Threat detected on this website.');
            setThreatInfo(threatInfo);
          });
        });
      } else {
        // Cache the safe URL
        chrome.storage.local.get(['safeUrls'], (result) => {
          const safeUrls = result.safeUrls || [];
          safeUrls.push(url);
          chrome.storage.local.set({safeUrls}, () => {
            setStatus('safe');
            setMessage('This website is safe to browse.');
          });
        });
      }
    }, 1500);
  };
  
  const toggleSettings = () => {
    setShowSettings(!showSettings);
  };
  
  const blockCurrentSite = () => {
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      const currentTab = tabs[0];
      chrome.tabs.update(currentTab.id, {url: 'blocked.html'});
    });
  };
  
  return (
    <div className="container">
      <div className="header">
        <h1>CipherLens</h1>
        <StatusBar status={status} message={message} />
        <div className="settings-icon" onClick={toggleSettings}>⚙️</div>
      </div>
      
      {!showSettings ? (
        <div className="content">
          {threatInfo && <ThreatDetails threatInfo={threatInfo} />}
        </div>
      ) : (
        <Settings onClose={toggleSettings} />
      )}
      
      <div className="footer">
        <button className="primary">Details</button>
        <button className="danger" onClick={blockCurrentSite}>Block Page</button>
      </div>
    </div>
  );
};

// Render the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('root');
  ReactDOM.render(<Popup />, root);
}); 