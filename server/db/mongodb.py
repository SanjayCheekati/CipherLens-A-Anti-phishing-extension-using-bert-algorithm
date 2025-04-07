import os
import logging
from pymongo import MongoClient, ASCENDING
from datetime import datetime

logger = logging.getLogger(__name__)

class MongoDB:
    def __init__(self):
        # Default to localhost with standard port for MongoDB Compass
        self.connection_string = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
        self.db_name = os.environ.get('MONGODB_DB_NAME', 'cipherlens')
        self.client = None
        self.db = None
        self.phishing_results = None
        self.feedback = None
        self.statistics = None
        
        # Try to connect on initialization
        self.connect()
        
    def connect(self):
        """Establish connection to MongoDB"""
        try:
            # Connect with a timeout for faster feedback
            self.client = MongoClient(self.connection_string, serverSelectionTimeoutMS=2000)
            
            # Test the connection
            self.client.admin.command('ping')
            
            # If we got here, connection is successful
            self.db = self.client[self.db_name]
            self.phishing_results = self.db.phishing_results
            self.feedback = self.db.feedback
            self.statistics = self.db.statistics
            
            # Create indexes for better performance
            self._create_indexes()
            
            logger.info(f"Connected to MongoDB successfully at {self.connection_string}")
            logger.info(f"Using database: {self.db_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            logger.error("Make sure MongoDB is running on your local machine")
            logger.error("You can download MongoDB Community Edition from https://www.mongodb.com/try/download/community")
            return False

    def _create_indexes(self):
        """Create necessary indexes on collections"""
        try:
            # Drop existing indexes to avoid conflicts
            try:
                self.phishing_results.drop_index("url_1")
            except Exception:
                # Index doesn't exist, which is fine
                pass
                
            # Create indexes for phishing_results collection
            self.phishing_results.create_index([("url", ASCENDING)], unique=True, name="url_index")
            self.phishing_results.create_index([("timestamp", ASCENDING)], name="timestamp_index")
            self.phishing_results.create_index([("is_phishing", ASCENDING)], name="phishing_flag_index")
            
            # Create indexes for feedback collection
            self.feedback.create_index([("url", ASCENDING)], name="feedback_url_index")
            self.feedback.create_index([("timestamp", ASCENDING)], name="feedback_timestamp_index")
            
            logger.info("Created indexes for collections")
        except Exception as e:
            logger.error(f"Error creating indexes: {str(e)}")
    
    def store_phishing_result(self, url, is_phishing, features, prediction_score, suspicious_elements=None, screenshot=None):
        """Store a phishing detection result"""
        if self.phishing_results is None:
            if not self.connect():
                return False
        
        try:
            result = {
                "url": url,
                "is_phishing": is_phishing,
                "prediction_score": prediction_score,
                "features": features,
                "timestamp": datetime.utcnow(),
                "suspicious_elements": suspicious_elements or [],
                "screenshot": screenshot
            }
            
            # Upsert based on URL to avoid duplicates
            self.phishing_results.update_one(
                {"url": url}, 
                {"$set": result},
                upsert=True
            )
            
            # Update statistics
            self._update_statistics(is_phishing)
            
            return True
        except Exception as e:
            logger.error(f"Failed to store phishing result: {str(e)}")
            return False
    
    def get_detection_by_url(self, url):
        """Get detection result by URL"""
        if self.phishing_results is None:
            if not self.connect():
                return None
        
        try:
            result = self.phishing_results.find_one({"url": url})
            return result
        except Exception as e:
            logger.error(f"Failed to get detection by URL: {str(e)}")
            return None

    def save_detection_result(self, result):
        """Save or update a detection result"""
        if self.phishing_results is None:
            if not self.connect():
                return None
        
        try:
            url = result.get("url")
            if not url:
                return None
                
            # Extract the _id if it exists
            _id = result.pop("_id", None)
            
            # Update with upsert
            update_result = self.phishing_results.update_one(
                {"url": url},
                {"$set": result},
                upsert=True
            )
            
            # If we inserted a new document
            if update_result.upserted_id:
                return update_result.upserted_id
                
            # If we updated an existing document
            if _id:
                return _id
                
            # Find the document to get its _id
            doc = self.phishing_results.find_one({"url": url})
            if doc:
                return doc.get("_id")
                
            return None
        except Exception as e:
            logger.error(f"Failed to save detection result: {str(e)}")
            return None

    def get_phishing_results(self, limit=100, skip=0, query=None):
        """Retrieve phishing detection results with pagination"""
        if self.phishing_results is None:
            if not self.connect():
                return []
        
        try:
            query = query or {}
            results = list(self.phishing_results.find(
                query, 
                {"screenshot": 0}  # Exclude large screenshot data
            ).sort("timestamp", -1).skip(skip).limit(limit))
            
            for result in results:
                if "_id" in result:
                    result["_id"] = str(result["_id"])
            
            return results
        except Exception as e:
            logger.error(f"Failed to retrieve phishing results: {str(e)}")
            return []

    def store_feedback(self, url, user_label, comments=None):
        """Store user feedback about a detection result"""
        if self.feedback is None:
            if not self.connect():
                return False
        
        try:
            feedback_data = {
                "url": url,
                "user_label": user_label,
                "comments": comments,
                "timestamp": datetime.utcnow()
            }
            
            self.feedback.insert_one(feedback_data)
            return True
        except Exception as e:
            logger.error(f"Failed to store feedback: {str(e)}")
            return False

    def get_statistics(self):
        """Get overall statistics from the database"""
        if self.statistics is None:
            if not self.connect():
                return {
                    "total_scans": 0,
                    "phishing_detected": 0,
                    "safe_sites": 0
                }
        
        try:
            stats = self.statistics.find_one({"_id": "global_stats"})
            if not stats:
                # Initialize statistics if not found
                stats = {
                    "_id": "global_stats",
                    "total_scans": 0,
                    "phishing_detected": 0,
                    "safe_sites": 0,
                    "last_updated": datetime.utcnow()
                }
                self.statistics.insert_one(stats)
            
            # Remove MongoDB _id
            if "_id" in stats:
                stats.pop("_id")
            return stats
        except Exception as e:
            logger.error(f"Failed to retrieve statistics: {str(e)}")
            return {
                "total_scans": 0,
                "phishing_detected": 0,
                "safe_sites": 0
            }

    def _update_statistics(self, is_phishing):
        """Update global statistics when new results are added"""
        try:
            update_data = {
                "$inc": {
                    "total_scans": 1,
                    "phishing_detected" if is_phishing else "safe_sites": 1
                },
                "$set": {
                    "last_updated": datetime.utcnow()
                }
            }
            
            self.statistics.update_one(
                {"_id": "global_stats"},
                update_data,
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to update statistics: {str(e)}")

    def close(self):
        """Close the MongoDB connection"""
        if self.client:
            self.client.close()
            self.client = None
            self.db = None
            self.phishing_results = None
            self.feedback = None
            self.statistics = None
            logger.info("MongoDB connection closed") 