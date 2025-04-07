# CipherLens

<p align="center">
  <img src="extension/assets/icon128.png" alt="CipherLens Logo" width="128" height="128">
</p>

<p align="center">
  <strong>AI-powered browser extension for real-time phishing detection and web threat protection</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#development">Development</a> •
  <a href="#license">License</a>
</p>

---

## Features

🔍 **Real-time Detection** - Identifies phishing attempts and suspicious websites as you browse

🧠 **Machine Learning Powered** - Analyzes URLs, domain metadata, and page content using advanced ML models

💻 **Visual Threat Indicators** - Instantly displays security status with clear visual warnings for risky sites

🔗 **Comprehensive URL Analysis** - Checks for IP addresses in URLs, suspicious TLDs, typosquatting, and other phishing indicators

🔒 **Privacy-Focused** - Runs locally and through your own server, no user data collection

📊 **Detection Statistics** - Keeps track of browsing protection statistics and threat categories

⚙️ **Customizable** - Configure detection sensitivity and notification preferences

## Architecture

CipherLens consists of two main components:

### 1. Chrome Extension (Frontend)
- **Content Scripts**: Analyze webpage content in real-time
- **Background Service**: Handles URL analysis and API communications
- **Popup Interface**: Provides user insights and controls

### 2. Python Server (Backend)
- **REST API**: Endpoints for URL analysis and threat detection
- **ML Models**: Machine learning model for phishing detection
- **MongoDB Database**: Stores detection results and statistics

## Installation

### Prerequisites
- Python 3.7 or higher
- Node.js and npm
- MongoDB (local or remote)
- Chrome or compatible Chromium-based browser

### Server Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/CipherLens.git
   cd CipherLens/server
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Make sure MongoDB is running on your system or accessible remotely.

5. Generate sample dataset (optional):
   ```bash
   python scripts/generate_and_load_dataset.py -n 200 --ratio 0.5 --clear-collection
   ```

6. Start the server:
   ```bash
   python app.py
   ```
   The server will run on `http://localhost:5000`

### Extension Setup

1. Navigate to the extension directory:
   ```bash
   cd CipherLens/extension
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the extension:
   ```bash
   npm run build
   ```

4. Load the extension in Chrome:
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top-right)
   - Click "Load unpacked" and select the `CipherLens/extension` directory

## Usage

### Basic Usage
1. After installation, the CipherLens icon will appear in your browser toolbar
2. The icon color indicates the safety status of the current site:
   - 🟢 Green: Safe site
   - 🔴 Red: Potential phishing or threat detected
   - ⚪ Gray: Site not yet analyzed

3. Click the extension icon to view detailed information and analysis of the current page

### Features
- **URL Scanning**: Every URL you visit is automatically checked for phishing indicators
- **Site Analysis**: Webpage content is analyzed for suspicious patterns
- **Manual Scanning**: Use the extension popup to manually scan any URL
- **Stats Dashboard**: View protection statistics and recent threat detections
- **Custom Rules**: Configure detection sensitivity in the extension settings

## Development

### Server Development

The server is built with Flask and uses a machine learning model to detect phishing sites.

```bash
cd server
python app.py --debug
```

#### Key Components:
- `app.py`: Main Flask application with API endpoints
- `models/phishing_detector.py`: ML model for phishing detection
- `db/mongodb.py`: Database connection and operations
- `utils/feature_extractor.py`: URL and content feature extraction

### Extension Development

```bash
cd extension
npm run dev
```

#### Key Components:
- `background.js`: Background service worker for URL analysis and API communication
- `popup.js`: User interface logic for the extension popup
- `contentScript.js`: Analysis of webpage content and DOM manipulation

## Dataset Information

The project includes scripts to generate simulated datasets:

```bash
# Generate balanced dataset (50% phishing, 50% legitimate)
python scripts/generate_and_load_dataset.py -n 200 --ratio 0.5 --clear-collection

# Generate high-risk dataset (70% phishing, 30% legitimate)
python scripts/generate_and_load_dataset.py -n 200 --ratio 0.3 --clear-collection
```

## Project Structure

```
CipherLens/
│
├── extension/             # Chrome extension
│   ├── assets/            # Images and static assets
│   ├── dist/              # Built extension files
│   ├── src/               # Source code
│   ├── manifest.json      # Extension manifest
│   └── package.json       # Node.js dependencies
│
└── server/                # Backend server
    ├── data/              # Sample datasets
    ├── db/                # Database connection modules
    ├── models/            # ML models
    ├── scripts/           # Data generation scripts
    ├── utils/             # Utility functions
    ├── app.py             # Main Flask application
    └── requirements.txt   # Python dependencies
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ for a safer web
</p> 