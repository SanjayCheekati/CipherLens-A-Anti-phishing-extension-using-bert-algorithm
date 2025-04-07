"""
MongoDB Connector for CipherLens
Provides database connection and CRUD operations for phishing detection results
"""
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, OperationFailure
from db.mongodb import MongoDB

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DBConnector:
    """
    Database connector class to provide a simplified interface for application database operations.
    This wraps around our MongoDB implementation to provide app-specific methods.
    """
    
    def __init__(self):
        self.db = MongoDB()
        self.connected = False
        
    def connect(self):
        """Establish connection to the database"""
        self.connected = self.db.connect()
        return self.connected
        
    def save_detection_result(self, result_data):
        """Save a detection result to the database"""
        try:
            url = result_data.get('url')
            is_phishing = result_data.get('is_phishing', False)
            features = result_data.get('features', {})
            prediction_score = result_data.get('score', 0.0)
            
            # Extract suspicious elements if available
            result = result_data.get('result', {})
            suspicious_elements = result.get('suspiciousElements', [])
            
            # No screenshot for now, but could be added in the future
            screenshot = None
            
            # Store in MongoDB
            success = self.db.store_phishing_result(
                url, 
                is_phishing, 
                features, 
                prediction_score, 
                suspicious_elements, 
                screenshot
            )
            
            if not success:
                logger.error(f"Failed to save detection result for URL: {url}")
                
            return success
        except Exception as e:
            logger.error(f"Error saving detection result: {str(e)}")
            return False
            
    def get_detection_by_url(self, url):
        """Retrieve a detection result by URL"""
        try:
            results = self.db.get_phishing_results(limit=1, query={"url": url})
            return results[0] if results else None
        except Exception as e:
            logger.error(f"Error retrieving detection by URL: {str(e)}")
            return None
            
    def save_user_feedback(self, feedback_data):
        """Save user feedback about a detection result"""
        try:
            url = feedback_data.get('url')
            user_label = feedback_data.get('is_correct', False)
            comments = feedback_data.get('comments', '')
            
            success = self.db.store_feedback(url, user_label, comments)
            if not success:
                logger.error(f"Failed to save user feedback for URL: {url}")
                
            return success
        except Exception as e:
            logger.error(f"Error saving user feedback: {str(e)}")
            return False
            
    def get_statistics(self):
        """Get overall statistics from the database"""
        try:
            stats = self.db.get_statistics()
            
            # Add extra calculated fields
            total_scans = stats.get('total_scans', 0)
            if total_scans > 0:
                stats['phishing_percentage'] = round(
                    (stats.get('phishing_detected', 0) / total_scans) * 100, 1
                )
                stats['safe_percentage'] = round(
                    (stats.get('safe_sites', 0) / total_scans) * 100, 1
                )
            else:
                stats['phishing_percentage'] = 0
                stats['safe_percentage'] = 0
                
            return stats
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {
                'total_scans': 0,
                'phishing_detected': 0,
                'safe_sites': 0,
                'phishing_percentage': 0,
                'safe_percentage': 0
            }
            
    def get_recent_detections(self, limit=10):
        """Get recent detection results"""
        try:
            results = self.db.get_phishing_results(limit=limit)
            
            # Format results for API response
            formatted_results = []
            for result in results:
                formatted_results.append({
                    'url': result.get('url'),
                    'isPhishing': result.get('is_phishing', False),
                    'score': result.get('prediction_score', 0.0),
                    'timestamp': result.get('timestamp').isoformat() if result.get('timestamp') else None,
                    'threatLevel': self._calculate_threat_level(result.get('prediction_score', 0.0))
                })
                
            return formatted_results
        except Exception as e:
            logger.error(f"Error getting recent detections: {str(e)}")
            return []
            
    def _calculate_threat_level(self, score):
        """Calculate threat level based on prediction score"""
        if score < 0.2:
            return "safe"
        elif score < 0.5:
            return "low"
        elif score < 0.8:
            return "medium"
        else:
            return "high"
            
    def close(self):
        """Close the database connection"""
        try:
            self.db.close()
            self.connected = False
        except Exception as e:
            logger.error(f"Error closing database connection: {str(e)}")

# Create a singleton instance for the application to use
db = DBConnector() 