import os
import sys
import logging
import traceback
from flask import Flask, request, jsonify, redirect, session, Response, make_response, render_template_string
from flask_cors import CORS
import shopify
import hmac
import hashlib
import base64
import datetime
from flask_session import Session
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(32))

# Basic configuration
SHOPIFY_API_KEY = os.environ.get('SHOPIFY_API_KEY')
SHOPIFY_API_SECRET = os.environ.get('SHOPIFY_API_SECRET')
APP_URL = os.environ.get('RENDER_EXTERNAL_URL', os.environ.get('APP_URL', 'http://localhost:8000'))
API_VERSION = '2023-10'

# Configure session
app.config.update(
    SESSION_TYPE='filesystem',
    SESSION_FILE_DIR='/tmp/flask_session',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=1)
)

# Initialize Flask-Session
Session(app)

# Allow CORS
CORS(app, supports_credentials=True)

def initialize_shopify():
    """Initialize Shopify API after app startup"""
    try:
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        versions = [str(version) for version in shopify.ApiVersion.versions]
        if API_VERSION not in versions:
            logger.error(f"Invalid API version: {API_VERSION}. Available versions: {versions}")
            return False
        logger.info(f"Shopify initialized with API version: {API_VERSION}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize Shopify: {str(e)}")
        return False

@app.before_first_request
def startup():
    """Initialize app on first request"""
    initialize_shopify()

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat()
    }), 200

# ... rest of your routes and code ... 