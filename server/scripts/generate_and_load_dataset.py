#!/usr/bin/env python
"""
CipherLens Dataset Generator and Loader
---------------------------------------
Generates a synthetic dataset of URLs and loads it into MongoDB
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime

# Add the parent directory to the path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Import our modules
from db.mongodb import MongoDB
from utils.feature_extractor import FeatureExtractor
from models.phishing_detector import PhishingDetector

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("dataset_loader")

def setup_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Generate and load a dataset into MongoDB.')
    parser.add_argument('-n', '--num-urls', type=int, default=500,
                        help='Number of URLs to generate (default: 500)')
    parser.add_argument('-i', '--input-file', type=str, default=None,
                        help='Input CSV file (if not generating data)')
    parser.add_argument('-s', '--seed', type=int, default=None,
                        help='Random seed for reproducibility')
    parser.add_argument('-r', '--ratio', type=float, default=0.6,
                        help='Ratio of legitimate to phishing URLs (default: 0.6)')
    parser.add_argument('--skip-generation', action='store_true',
                        help='Skip dataset generation, just load existing file')
    parser.add_argument('--clear-collection', action='store_true',
                        help='Clear the MongoDB collection before loading data')
    
    return parser.parse_args()

def generate_dataset(args):
    """Generate the dataset using our generator script."""
    import subprocess
    
    cmd = ['python', os.path.join(parent_dir, 'scripts', 'generate_dataset.py')]
    
    if args.num_urls:
        cmd.extend(['-n', str(args.num_urls)])
    if args.seed:
        cmd.extend(['-s', str(args.seed)])
    if args.ratio:
        cmd.extend(['-r', str(args.ratio)])
    
    output_file = os.path.join(parent_dir, 'data', 'phishing_dataset.csv')
    cmd.extend(['-o', output_file])
    
    logger.info(f"Running command: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, cwd=parent_dir, capture_output=True, text=True)
    
    if result.returncode != 0:
        logger.error(f"Error generating dataset: {result.stderr}")
        sys.exit(1)
    
    logger.info(result.stdout.strip())
    
    # Return the path to the generated file
    return output_file

def load_dataset_into_mongodb(file_path, clear_collection=False):
    """Load the dataset into MongoDB."""
    import csv
    
    # Initialize components
    db = MongoDB()
    feature_extractor = FeatureExtractor()
    phishing_detector = PhishingDetector()
    phishing_detector.initialize()
    
    # Connect to MongoDB
    if not db.connect():
        logger.error("Failed to connect to MongoDB")
        logger.error("Make sure MongoDB is running on localhost:27017")
        return False
    
    # Clear collection if requested
    if clear_collection and db.phishing_results is not None:
        logger.info("Clearing existing data from phishing_results collection")
        try:
            db.phishing_results.delete_many({})
            # Reset statistics
            db.statistics.update_one(
                {"_id": "global_stats"},
                {"$set": {
                    "total_scans": 0,
                    "phishing_detected": 0,
                    "safe_sites": 0,
                    "last_updated": datetime.utcnow()
                }},
                upsert=True
            )
            logger.info("Collection cleared successfully")
        except Exception as e:
            logger.error(f"Error clearing collection: {str(e)}")
    
    logger.info(f"Loading dataset from {file_path}")
    
    try:
        count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row['url']
                is_phishing = row['is_phishing'] == '1' or row['is_phishing'].lower() == 'true'
                category = row['category']
                risk_level = row['risk_level']
                
                # Extract features using our extractor
                features = feature_extractor.extract_from_url(url)
                
                # Get prediction score using our model
                prediction = phishing_detector.predict(features)
                prediction_score = prediction.get('score', 0.5 if is_phishing else 0.1)
                
                # Add some randomness to make it realistic
                if 'features' in row and row['features'].startswith('{'):
                    try:
                        # If features string is a valid JSON, parse it
                        row_features = eval(row['features'])
                        # Add these features to our extracted features
                        for key, value in row_features.items():
                            if key not in features:
                                features[key] = value
                    except Exception as e:
                        logger.debug(f"Failed to parse features: {str(e)}")
                
                # Create suspicious elements based on features
                suspicious_elements = []
                if is_phishing:
                    if features.get('hasIPAddress', False):
                        suspicious_elements.append("IP address in domain")
                    if features.get('hasSuspiciousTLD', False):
                        suspicious_elements.append("Suspicious top-level domain")
                    if features.get('hasAtSymbol', False):
                        suspicious_elements.append("URL contains @ symbol")
                    if features.get('hasLongURL', False) or features.get('urlLength', 0) > 0.5:
                        suspicious_elements.append("Excessively long URL")
                
                # Store in MongoDB
                success = db.store_phishing_result(
                    url=url,
                    is_phishing=is_phishing,
                    features=features,
                    prediction_score=prediction_score,
                    suspicious_elements=suspicious_elements
                )
                
                if not success:
                    logger.warning(f"Failed to save record for URL: {url}")
                    continue
                
                count += 1
                if count % 50 == 0:
                    logger.info(f"Loaded {count} URLs into MongoDB")
        
        logger.info(f"Successfully loaded {count} URLs into MongoDB")
        
        # Print statistics
        stats = db.get_statistics()
        logger.info(f"Database statistics:")
        logger.info(f"  Total scans: {stats.get('total_scans', 0)}")
        logger.info(f"  Phishing detected: {stats.get('phishing_detected', 0)}")
        logger.info(f"  Safe sites: {stats.get('safe_sites', 0)}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error loading dataset: {str(e)}")
        return False
    finally:
        # Close MongoDB connection
        db.close()

def main():
    """Main function."""
    args = setup_args()
    
    # Generate dataset if needed
    if args.skip_generation and args.input_file:
        file_path = args.input_file
    elif args.skip_generation:
        file_path = os.path.join(parent_dir, 'data', 'phishing_dataset.csv')
        if not os.path.exists(file_path):
            logger.error(f"Skipping generation but dataset file not found: {file_path}")
            sys.exit(1)
    else:
        file_path = generate_dataset(args)
    
    # Verify file exists
    if not os.path.exists(file_path):
        logger.error(f"Dataset file not found: {file_path}")
        sys.exit(1)
    
    # Load dataset into MongoDB
    success = load_dataset_into_mongodb(file_path, clear_collection=args.clear_collection)
    
    if success:
        logger.info("Dataset successfully loaded into MongoDB")
        logger.info("You can now view the data in MongoDB Compass by connecting to:")
        logger.info("mongodb://localhost:27017/")
        logger.info("Database: cipherlens")
        logger.info("Collections: phishing_results, statistics, feedback")
    else:
        logger.error("Failed to load dataset into MongoDB")
        sys.exit(1)

if __name__ == "__main__":
    main() 