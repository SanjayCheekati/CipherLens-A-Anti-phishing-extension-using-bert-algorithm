from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from datetime import datetime
import uuid

# Import the custom modules
from models.phishing_detector import PhishingDetector
from models.explainer import Explainer
from utils.feature_extractor import FeatureExtractor
from db.mongodb import MongoDB

# Initialize MongoDB connection
db = MongoDB()

# Initialize the application
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize the models
phishing_detector = PhishingDetector()
explainer = Explainer()
feature_extractor = FeatureExtractor()

# Store detection results in memory (would use a database in production)
detection_results = {}
feedback_data = []

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    # Check MongoDB connection
    try:
        # Try to ping MongoDB
        is_connected = db.connect()
        mongodb_status = "connected" if is_connected else "disconnected"
    except Exception as e:
        mongodb_status = f"disconnected ({str(e)})"
    
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'mongodb': mongodb_status
    })

# API info endpoint
@app.route('/api/info', methods=['GET'])
def api_info():
    return jsonify({
        'success': True,
        'name': 'CipherLens API',
        'version': '1.0.0',
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'features': [
            'Phishing URL Detection',
            'Content Analysis',
            'SHAP/LIME Explanations',
            'Suspicious Element Detection',
            'MongoDB Integration'
        ]
    })

# Phishing detection endpoints
@app.route('/api/detect/url', methods=['POST'])
def detect_phishing_url():
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            'success': False,
            'error': 'URL is required'
        }), 400
    
    url = data['url']
    
    # Check if we already have this URL in the database
    existing_detection = db.get_detection_by_url(url)
    if existing_detection:
        # Return cached result if it exists and is recent (within 24 hours)
        detection_time = existing_detection.get("created_at")
        current_time = datetime.now()
        
        # If detection is less than 24 hours old, return cached result
        if detection_time and (current_time - detection_time).total_seconds() < 86400:
            return jsonify({
                'success': True,
                'cached': True,
                'taskId': existing_detection.get("_id", str(uuid.uuid4())),
                'status': 'completed',
                'result': existing_detection.get("result"),
                'url': url
            })
    
    # Create a unique task ID
    task_id = str(uuid.uuid4())
    
    # Extract features from URL
    features = feature_extractor.extract_from_url(url)
    
    # Store the task (still keep in-memory for backward compatibility)
    detection_results[task_id] = {
        'url': url,
        'features': features,
        'status': 'processing',
        'created_at': datetime.now().isoformat()
    }
    
    # In a real application, this would be processed asynchronously
    # For simplicity, we'll process it immediately
    try:
        result = phishing_detector.predict(features)
        
        # Update in-memory store
        detection_results[task_id].update({
            'result': result,
            'status': 'completed',
            'completed_at': datetime.now().isoformat()
        })
        
        # Save to database
        db_result = {
            'task_id': task_id,
            'url': url, 
            'features': features,
            'result': result,
            'is_phishing': result['isPhishing'],
            'score': result['score'],
            'confidence': result['confidence'],
            'threat_level': result['threatLevel'],
            'explanations': result['explanations'],
            'completed_at': datetime.now()
        }
        
        # Save to MongoDB
        db_id = db.save_detection_result(db_result)
        
        return jsonify({
            'success': True,
            'taskId': task_id,
            'status': 'completed',
            'result': result,
            'url': url
        })
    except Exception as e:
        detection_results[task_id].update({
            'status': 'failed',
            'error': str(e),
            'completed_at': datetime.now().isoformat()
        })
        return jsonify({
            'success': False,
            'error': f'Error processing detection: {str(e)}',
            'taskId': task_id
        }), 500

@app.route('/api/detect/content', methods=['POST'])
def detect_phishing_content():
    data = request.get_json()
    
    if not data or 'url' not in data or 'content' not in data:
        return jsonify({
            'success': False,
            'error': 'URL and content are required'
        }), 400
    
    url = data['url']
    content = data['content']
    
    # Check if we already have this URL in the database
    existing_detection = db.get_detection_by_url(url)
    if existing_detection:
        # Return cached result if it exists and is recent (within 24 hours)
        detection_time = existing_detection.get("created_at")
        current_time = datetime.now()
        
        # If detection is less than 24 hours old, return cached result
        if detection_time and (current_time - detection_time).total_seconds() < 86400:
            return jsonify({
                'success': True,
                'cached': True,
                'taskId': existing_detection.get("_id", str(uuid.uuid4())),
                'status': 'completed',
                'result': existing_detection.get("result"),
                'url': url
            })
    
    # Create a unique task ID
    task_id = str(uuid.uuid4())
    
    # Extract features
    url_features = feature_extractor.extract_from_url(url)
    content_features = feature_extractor.extract_from_content(content)
    
    # Combine features
    features = {**url_features, **content_features}
    
    # Store the task (still keep in-memory for backward compatibility)
    detection_results[task_id] = {
        'url': url,
        'features': features,
        'status': 'processing',
        'created_at': datetime.now().isoformat()
    }
    
    # Process it (would be async in production)
    try:
        result = phishing_detector.predict(features)
        
        # Update in-memory store
        detection_results[task_id].update({
            'result': result,
            'status': 'completed',
            'completed_at': datetime.now().isoformat()
        })
        
        # Save to database
        db_result = {
            'task_id': task_id,
            'url': url, 
            'features': features,
            'result': result,
            'is_phishing': result['isPhishing'],
            'score': result['score'],
            'confidence': result['confidence'],
            'threat_level': result['threatLevel'],
            'explanations': result['explanations'],
            'has_content_analysis': True,
            'completed_at': datetime.now()
        }
        
        # Save to MongoDB
        db_id = db.save_detection_result(db_result)
        
        return jsonify({
            'success': True,
            'taskId': task_id,
            'status': 'completed',
            'result': result,
            'url': url
        })
    except Exception as e:
        detection_results[task_id].update({
            'status': 'failed',
            'error': str(e),
            'completed_at': datetime.now().isoformat()
        })
        return jsonify({
            'success': False,
            'error': f'Error processing detection: {str(e)}',
            'taskId': task_id
        }), 500

@app.route('/api/detect/status/<task_id>', methods=['GET'])
def get_detection_status(task_id):
    # First check in-memory cache
    if task_id in detection_results:
        task = detection_results[task_id]
        
        if task['status'] == 'completed':
            return jsonify({
                'success': True,
                'status': task['status'],
                'result': task['result'],
                'url': task['url'],
                'completedAt': task['completed_at']
            })
        elif task['status'] == 'failed':
            return jsonify({
                'success': False,
                'status': task['status'],
                'error': task.get('error', 'Detection failed'),
                'url': task['url']
            })
        else:
            return jsonify({
                'success': True,
                'status': task['status'],
                'url': task['url'],
                'message': 'Detection is still processing'
            })
    
    # If not in memory, check database
    # In a real application, we would look up by task_id in the database
    return jsonify({
        'success': False,
        'error': 'Task not found'
    }), 404

# Explainer endpoints
@app.route('/api/explain/features', methods=['POST'])
def explain_features():
    data = request.get_json()
    
    if not data or 'features' not in data:
        return jsonify({
            'success': False,
            'error': 'Features are required'
        }), 400
    
    features = data['features']
    explainer_type = data.get('explainer', 'shap').lower()
    
    try:
        explanations = explainer.explain_prediction(features, explainer_type)
        return jsonify({
            'success': True,
            'explanations': explanations,
            'explainer': explainer_type
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error generating explanations: {str(e)}'
        }), 500

@app.route('/api/explain/html', methods=['POST'])
def explain_with_html():
    data = request.get_json()
    
    if not data or 'features' not in data:
        return jsonify({
            'success': False,
            'error': 'Features are required'
        }), 400
    
    features = data['features']
    explainer_type = data.get('explainer', 'shap').lower()
    
    try:
        explanations = explainer.explain_prediction(features, explainer_type)
        visualization = explainer.generate_visualization(explanations)
        return jsonify({
            'success': True,
            'explanations': explanations,
            'visualization': visualization,
            'explainer': explainer_type
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error generating HTML explanations: {str(e)}'
        }), 500

@app.route('/api/explain/elements', methods=['POST'])
def explain_suspicious_elements():
    data = request.get_json()
    
    if not data or 'html' not in data or 'features' not in data:
        return jsonify({
            'success': False,
            'error': 'HTML content and features are required'
        }), 400
    
    html_content = data['html']
    features = data['features']
    explainer_type = data.get('explainer', 'shap').lower()
    
    try:
        explanations = explainer.explain_prediction(features, explainer_type)
        suspicious_elements = explainer.identify_suspicious_elements(html_content, explanations)
        
        return jsonify({
            'success': True,
            'suspiciousElements': suspicious_elements,
            'explanations': explanations,
            'explainer': explainer_type
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error identifying suspicious elements: {str(e)}'
        }), 500

# Feedback endpoints
@app.route('/api/feedback/submit', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    
    if not data or 'url' not in data or 'isCorrect' not in data:
        return jsonify({
            'success': False,
            'error': 'URL and feedback status are required'
        }), 400
    
    url = data['url']
    is_correct = data['isCorrect']
    comments = data.get('comments', '')
    
    try:
        # Get detection from database
        detection = db.get_detection_by_url(url)
        
        if not detection:
            return jsonify({
                'success': False,
                'error': 'No detection found for this URL'
            }), 404
        
        # Save feedback to database
        feedback = {
            'detection_id': detection.get('_id'),
            'url': url,
            'is_correct': is_correct,
            'comments': comments,
            'created_at': datetime.now()
        }
        
        db_id = db.save_user_feedback(feedback)
        
        return jsonify({
            'success': True,
            'message': 'Feedback submitted successfully',
            'feedbackId': db_id
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error submitting feedback: {str(e)}'
        }), 500

# New endpoint for getting statistics
@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    try:
        stats = db.get_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error retrieving statistics: {str(e)}'
        }), 500

# New endpoint for getting recent detections
@app.route('/api/recent-detections', methods=['GET'])
def get_recent_detections():
    limit = request.args.get('limit', 10, type=int)
    
    try:
        detections = db.get_recent_detections(limit)
        
        return jsonify({
            'success': True,
            'detections': detections
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error retrieving recent detections: {str(e)}'
        }), 500

# New endpoint for loading sample dataset
@app.route('/api/dataset/load', methods=['GET'])
def load_sample_dataset():
    import csv
    import os.path
    
    try:
        dataset_path = os.path.join(os.path.dirname(__file__), 'data', 'phishing_dataset_sample.csv')
        
        if not os.path.exists(dataset_path):
            return jsonify({
                'success': False,
                'error': 'Sample dataset file not found'
            }), 404
        
        urls_processed = 0
        
        with open(dataset_path, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                url = row['url']
                is_phishing = row['is_phishing'] == '1'
                
                # Skip if already in database
                if db.get_detection_by_url(url):
                    continue
                
                # Extract features
                features = feature_extractor.extract_from_url(url)
                
                # Predict using model
                result = phishing_detector.predict(features)
                
                # Save to database
                db_result = {
                    'task_id': str(uuid.uuid4()),
                    'url': url, 
                    'features': features,
                    'result': result,
                    'is_phishing': result['isPhishing'],
                    'score': result['score'],
                    'confidence': result['confidence'],
                    'threat_level': result['threatLevel'],
                    'explanations': result['explanations'],
                    'category': row['category'],
                    'dataset_label': is_phishing,
                    'completed_at': datetime.now()
                }
                
                db.save_detection_result(db_result)
                urls_processed += 1
        
        return jsonify({
            'success': True,
            'message': f'Successfully loaded {urls_processed} URLs from sample dataset'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error loading sample dataset: {str(e)}'
        }), 500

if __name__ == '__main__':
    # Ensure database connection
    db.connect()
        
    # Initialize phishing detector
    phishing_detector.initialize()
    
    # Start the server
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True) 