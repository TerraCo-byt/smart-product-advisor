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
API_VERSION = '2023-04'

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

# Define scopes
SCOPES = ['read_products', 'write_products', 'read_themes', 'write_themes']

def initialize_shopify():
    """Initialize Shopify API after app startup"""
    try:
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        versions = [str(version) for version in shopify.ApiVersion.versions]
        if API_VERSION not in versions:
            logger.error(f"Invalid API version: {API_VERSION}. Available versions: {versions}")
            return False
        logger.info(f"Shopify initialized with API version: {API_VERSION}")
        logger.info(f"Available versions: {versions}")
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

@app.route('/')
def home():
    """Root route - redirects to install if shop parameter is present"""
    try:
        shop = request.args.get('shop')
        if shop:
            return redirect(f"/install?shop={shop}")
            
        return """
        <!DOCTYPE html>
        <html>
            <head>
                <title>Smart Product Advisor</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
            </head>
            <body>
                <h1>Smart Product Advisor</h1>
                <p>Welcome to Smart Product Advisor. Please install this app from the Shopify App Store.</p>
            </body>
        </html>
        """
    except Exception as e:
        logger.error(f"Home route error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/install')
def install():
    """Initial route for app installation"""
    try:
        shop = request.args.get('shop')
        host = request.args.get('host', '')
        embedded = request.args.get('embedded', '1')
        
        if not shop:
            logger.error("Missing shop parameter")
            return jsonify({"error": "Missing shop parameter"}), 400
            
        logger.info(f"Installation requested for shop: {shop}")
        
        # Generate state for OAuth
        state = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Create permission URL
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, API_VERSION)
        redirect_uri = f"{APP_URL}/auth/callback"
        
        auth_url = shopify_session.create_permission_url(
            SCOPES,
            redirect_uri,
            state
        )
        
        # Add additional parameters
        if host:
            auth_url += f"&host={host}"
        if embedded:
            auth_url += f"&embedded={embedded}"
            
        logger.info(f"Generated auth URL: {auth_url}")
        
        # Store state in session
        session['state'] = state
        session['shop'] = shop
        session.permanent = True
        
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Installation error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route('/auth/callback')
def callback():
    """Handle OAuth callback from Shopify"""
    try:
        shop = request.args.get('shop')
        
        if not shop:
            return jsonify({"error": "Missing shop parameter"}), 400
            
        # Verify state
        state = request.args.get('state')
        stored_state = session.get('state')
        if not state or not stored_state or state != stored_state:
            return redirect(f"/install?shop={shop}")
            
        # Setup Shopify session
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, API_VERSION)
        
        try:
            access_token = shopify_session.request_token(request.args)
            session['access_token'] = access_token
            session['shop'] = shop
            
            return redirect(f"/app?shop={shop}")
            
        except Exception as e:
            logger.error(f"Error requesting access token: {str(e)}")
            return redirect(f"/install?shop={shop}")
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        return redirect(f"/install?shop={shop}")

@app.route('/app')
def app_page():
    """Main app page that loads in the Shopify Admin"""
    try:
        shop = request.args.get('shop')
        host = request.args.get('host')
        
        if not shop:
            return jsonify({"error": "Missing shop parameter"}), 400

        # Check if we have a valid session
        if session.get('shop') != shop or not session.get('access_token'):
            return redirect(f"/install?shop={shop}")
            
        # Create response with HTML content
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Smart Product Advisor</title>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <script src="https://unpkg.com/@shopify/app-bridge@3"></script>
                    <script src="https://unpkg.com/@shopify/app-bridge-utils@3"></script>
                    <script>
                        document.addEventListener('DOMContentLoaded', function() {
                            const host = decodeURIComponent('{{ host }}');
                            const shop = '{{ shop }}';
                            
                            if (!host || !shop) {
                                console.error('Missing required parameters');
                                return;
                            }
                            
                            const config = {
                                apiKey: '{{ api_key }}',
                                host: host,
                                forceRedirect: true
                            };
                            
                            try {
                                const createApp = window['app-bridge'].default;
                                const app = createApp(config);
                                
                                // Create the title bar
                                const TitleBar = window['app-bridge'].actions.TitleBar;
                                TitleBar.create(app, {
                                    title: 'Smart Product Advisor',
                                    buttons: {
                                        primary: {
                                            label: 'Get Recommendations',
                                            callback: () => {
                                                console.log('Getting recommendations...');
                                            }
                                        }
                                    }
                                });
                            } catch (error) {
                                console.error('Error initializing app:', error);
                                document.getElementById('error-message').textContent = 'Error initializing app. Please try refreshing the page.';
                            }
                        });
                    </script>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                            margin: 0;
                            padding: 20px;
                        }
                        .app-container {
                            max-width: 800px;
                            margin: 0 auto;
                        }
                        .error-message {
                            color: #d82c0d;
                            display: none;
                            margin-top: 1em;
                        }
                        .error-message.visible {
                            display: block;
                        }
                    </style>
                </head>
                <body>
                    <div class="app-container">
                        <h1>Smart Product Advisor</h1>
                        <p>Loading your product recommendations...</p>
                        <p id="error-message" class="error-message"></p>
                    </div>
                </body>
            </html>
        """, api_key=SHOPIFY_API_KEY, host=host, shop=shop))
        
        # Set security headers
        response.headers.update({
            'Content-Security-Policy': (
                "frame-ancestors https://*.myshopify.com "
                "https://admin.shopify.com "
                "https://*.shopify.com "
                "https://partners.shopify.com"
            ),
            'Content-Type': 'text/html; charset=utf-8'
        })
        
        return response
        
    except Exception as e:
        logger.error(f"App page error: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port) 