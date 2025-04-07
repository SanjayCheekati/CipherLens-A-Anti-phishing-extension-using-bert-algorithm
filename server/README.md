# CipherLens Backend

This is the Python-based backend server for CipherLens, an AI-powered browser extension for real-time web threat detection.

## Features

- Real-time phishing detection API
- SHAP/LIME explainable AI integration
- Feature extraction from URLs and webpage content
- Suspicious element detection in HTML content

## Setup

### Requirements

- Python 3.7+
- pip (Python package manager)

### Installation

1. Create a virtual environment (recommended):
   ```
   python -m venv venv
   ```

2. Activate the virtual environment:
   - Windows:
     ```
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```
     source venv/bin/activate
     ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Running the Server

Start the development server:

```
python app.py
```

The server will be available at http://localhost:5000

## API Endpoints

- `GET /health` - Health check
- `GET /api/info` - API information
- `POST /api/detect/url` - Analyze a URL for phishing attempts
- `POST /api/detect/content` - Analyze webpage content for phishing attempts
- `GET /api/detect/status/:id` - Get status of a detection task
- `POST /api/explain/features` - Generate explanations for features
- `POST /api/explain/html` - Generate HTML visualization for explanations
- `POST /api/explain/elements` - Identify suspicious elements in HTML
- `POST /api/feedback` - Submit feedback about detection results
- `GET /api/stats` - Get detection statistics

## Development

### Running Tests

```
pytest
```

### Formatting Code

```
black .
``` 