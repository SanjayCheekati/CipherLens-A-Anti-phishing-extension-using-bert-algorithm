"""
Explainer - A simplified model for explaining threat detections

In a real extension, this would be a SHAP or LIME-based explainer
For demonstration purposes, this uses simplified feature attribution
"""
import time
import logging
import re
from typing import Dict, List, Any, Union
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Explainer:
    def __init__(self):
        self.initialized = False
        
        # Map feature names to user-friendly descriptions
        self.feature_descriptions = {
            "hasIPAddress": "Use of IP address in URL",
            "urlLength": "Unusually long URL",
            "hasAtSymbol": "URL contains @ symbol",
            "hasManySubdomains": "Multiple subdomains",
            "hasSuspiciousTLD": "Suspicious top-level domain",
            "hasHyphens": "Multiple hyphens in domain",
            "hasPasswordField": "Password input field",
            "hasSensitiveKeywords": "Sensitive keywords",
            "mismatchedFormAction": "Form submits to different domain",
            "isNotHttps": "Non-secure connection",
            "hasCertificateIssues": "SSL certificate issues"
        }
    
    def initialize(self) -> bool:
        """Initialize the explainer (in a real implementation, this would load the SHAP/LIME model)"""
        logger.info("Initializing explainer model...")
        
        # Simulate loading time
        time.sleep(0.5)
        
        self.initialized = True
        logger.info("Explainer model initialized")
        return True
    
    def explain_prediction(self, features: Dict[str, float], explainer_type: str = "shap") -> List[Dict[str, Any]]:
        """
        Generate explanations for a phishing prediction
        
        Args:
            features: Extracted features
            explainer_type: Type of explainer to use ("shap" or "lime")
            
        Returns:
            List of explanation objects
        """
        if not self.initialized:
            self.initialize()
        
        # Calculate feature attributions (in a real system, this would be SHAP/LIME values)
        attributions = {}
        total_attribution = 0
        
        for feature, value in features.items():
            if value > 0:
                # For demonstration, we'll use the feature value as attribution
                attribution = value
                attributions[feature] = attribution
                total_attribution += attribution
        
        # Normalize attributions to percentages
        normalized_attributions = {}
        if total_attribution > 0:
            for feature, attribution in attributions.items():
                normalized_attributions[feature] = (attribution / total_attribution) * 100
        
        # Convert to array and sort by attribution value (descending)
        sorted_explanations = [
            {
                "feature": feature,
                "description": self.feature_descriptions.get(feature, feature),
                "attribution": attribution,
                "value": features.get(feature, 0)
            }
            for feature, attribution in normalized_attributions.items()
        ]
        
        sorted_explanations.sort(key=lambda x: x["attribution"], reverse=True)
        
        return sorted_explanations
    
    def generate_visualization(self, explanations: List[Dict[str, Any]]) -> str:
        """
        Generate HTML to visualize feature contributions
        
        Args:
            explanations: List of explanation objects
            
        Returns:
            HTML string for visualization
        """
        if not explanations:
            return '<div class="empty-explanation">No significant factors found.</div>'
        
        # Create HTML for visualization
        html = '<div class="explanation-container">'
        
        for exp in explanations:
            bar_width = max(5, exp["attribution"])  # Minimum 5% width for visibility
            
            html += f'''
                <div class="explanation-item">
                    <div class="explanation-label">{exp["description"]}</div>
                    <div class="explanation-bar-container">
                        <div class="explanation-bar" style="width: {bar_width}%"></div>
                        <div class="explanation-value">{exp["attribution"]:.1f}%</div>
                    </div>
                </div>
            '''
        
        html += '</div>'
        return html
    
    def identify_suspicious_elements(self, html_content: str, explanations: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Extract suspicious elements from the HTML based on feature attributions
        
        Args:
            html_content: The webpage HTML
            explanations: List of explanation objects
            
        Returns:
            List of suspicious elements with descriptions
        """
        suspicious_elements = []
        
        # Parse HTML
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract relevant features from explanations
            important_features = [exp["feature"] for exp in explanations[:3]]
            
            # Check for suspicious elements based on important features
            if "hasPasswordField" in important_features:
                password_fields = soup.find_all("input", {"type": "password"})
                for field in password_fields:
                    suspicious_elements.append({
                        "element": "Password input field",
                        "description": "Sensitive data collection",
                        "selector": self._get_selector(field)
                    })
            
            if "mismatchedFormAction" in important_features:
                forms = soup.find_all("form")
                for form in forms:
                    if form.get("action") and not form["action"].startswith("#"):
                        suspicious_elements.append({
                            "element": "Form",
                            "description": f"Submits data to external domain: {form['action']}",
                            "selector": self._get_selector(form)
                        })
            
            if "hasSensitiveKeywords" in important_features:
                # Look for elements with sensitive keywords
                sensitive_keywords = [
                    "password", "credit card", "login", "signin", "bank", "account",
                    "social security", "ssn", "credentials"
                ]
                
                for keyword in sensitive_keywords:
                    elements = soup.find_all(text=re.compile(keyword, re.IGNORECASE))
                    for element in elements:
                        parent = element.parent
                        if parent:
                            suspicious_elements.append({
                                "element": parent.name,
                                "description": f"Contains sensitive keyword: {keyword}",
                                "selector": self._get_selector(parent)
                            })
        
        except Exception as e:
            logger.error(f"Error identifying suspicious elements: {str(e)}")
        
        return suspicious_elements
    
    def _get_selector(self, element) -> str:
        """Generate a CSS selector for an element (simplified)"""
        if element.get('id'):
            return f"#{element['id']}"
        
        if element.get('class'):
            classes = '.'.join(element['class'])
            return f".{classes}"
        
        # Fallback to element type
        return element.name 