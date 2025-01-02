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
        host = request.args.get('host', '')
        embedded = request.args.get('embedded', '1')
        
        if not shop:
            return jsonify({"error": "Missing shop parameter"}), 400
            
        logger.info(f"Auth callback received for shop: {shop}")
        logger.info(f"Host parameter: {host}")
            
        # Verify state
        state = request.args.get('state')
        stored_state = session.get('state')
        if not state or not stored_state or state != stored_state:
            return redirect(f"/install?shop={shop}&host={host}&embedded={embedded}")
            
        # Setup Shopify session
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, API_VERSION)
        
        try:
            access_token = shopify_session.request_token(request.args)
            session['access_token'] = access_token
            session['shop'] = shop
            
            # Redirect to app page with all necessary parameters
            app_url = f"/app?shop={shop}"
            if host:
                app_url += f"&host={host}"
            if embedded:
                app_url += f"&embedded={embedded}"
                
            logger.info(f"Redirecting to app URL: {app_url}")
            return redirect(app_url)
            
        except Exception as e:
            logger.error(f"Error requesting access token: {str(e)}")
            return redirect(f"/install?shop={shop}&host={host}&embedded={embedded}")
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(f"/install?shop={shop}")

@app.route('/app')
def app_page():
    """Main app page that loads in the Shopify Admin"""
    try:
        shop = request.args.get('shop')
        host = request.args.get('host')
        embedded = request.args.get('embedded', '1')
        
        logger.info(f"App page requested for shop: {shop}")
        logger.info(f"Host parameter: {host}")
        logger.info(f"Embedded parameter: {embedded}")
        
        if not shop:
            return jsonify({"error": "Missing shop parameter"}), 400

        # Check if we have a valid session
        if session.get('shop') != shop or not session.get('access_token'):
            install_url = f"/install?shop={shop}"
            if host:
                install_url += f"&host={host}"
            if embedded:
                install_url += f"&embedded={embedded}"
            return redirect(install_url)
            
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
                            
                            console.log('Host:', host);
                            console.log('Shop:', shop);
                            
                            if (!host || !shop) {
                                console.error('Missing required parameters');
                                document.getElementById('error-message').textContent = 'Missing required parameters';
                                document.getElementById('error-message').classList.add('visible');
                                return;
                            }
                            
                            try {
                                const config = {
                                    apiKey: '{{ api_key }}',
                                    host: host,
                                    forceRedirect: true
                                };
                                
                                console.log('App Bridge Config:', config);
                                
                                const AppBridge = window['app-bridge'];
                                const createApp = AppBridge.default;
                                const app = createApp(config);
                                
                                // Create the title bar
                                const TitleBar = AppBridge.actions.TitleBar;
                                TitleBar.create(app, {
                                    title: 'Smart Product Advisor',
                                    buttons: {
                                        primary: {
                                            label: 'Get Recommendations',
                                            callback: () => {
                                                document.getElementById('recommendation-form').submit();
                                            }
                                        }
                                    }
                                });
                                
                                // Hide loading message once app is initialized
                                document.getElementById('loading-message').style.display = 'none';
                                document.getElementById('app-content').style.display = 'block';
                                
                            } catch (error) {
                                console.error('Error initializing app:', error);
                                document.getElementById('error-message').textContent = 'Error initializing app: ' + error.message;
                                document.getElementById('error-message').classList.add('visible');
                                document.getElementById('loading-message').style.display = 'none';
                            }
                        });
                    </script>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                            margin: 0;
                            padding: 20px;
                            background-color: #f6f6f7;
                        }
                        .app-container {
                            max-width: 800px;
                            margin: 0 auto;
                            background-color: white;
                            padding: 20px;
                            border-radius: 8px;
                            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                        }
                        .error-message {
                            color: #d82c0d;
                            display: none;
                            margin-top: 1em;
                            padding: 1em;
                            background-color: #fbeae5;
                            border-radius: 4px;
                        }
                        .error-message.visible {
                            display: block;
                        }
                        #app-content {
                            display: none;
                        }
                        .loading {
                            text-align: center;
                            padding: 2em;
                            color: #637381;
                        }
                        .form-group {
                            margin-bottom: 1.5em;
                        }
                        .form-group label {
                            display: block;
                            margin-bottom: 0.5em;
                            font-weight: 500;
                            color: #212b36;
                        }
                        .form-group input,
                        .form-group select {
                            width: 100%;
                            padding: 0.5em;
                            border: 1px solid #c4cdd5;
                            border-radius: 4px;
                            font-size: 1em;
                        }
                        .form-group input:focus,
                        .form-group select:focus {
                            outline: none;
                            border-color: #5c6ac4;
                            box-shadow: 0 0 0 1px #5c6ac4;
                        }
                        .tag-input {
                            display: flex;
                            flex-wrap: wrap;
                            gap: 0.5em;
                            padding: 0.5em;
                            border: 1px solid #c4cdd5;
                            border-radius: 4px;
                            min-height: 2.5em;
                        }
                        .tag {
                            background-color: #f4f6f8;
                            border: 1px solid #c4cdd5;
                            border-radius: 3px;
                            padding: 0.25em 0.5em;
                            display: flex;
                            align-items: center;
                            gap: 0.5em;
                        }
                        .tag button {
                            border: none;
                            background: none;
                            color: #637381;
                            cursor: pointer;
                            padding: 0;
                            font-size: 1.2em;
                            line-height: 1;
                        }
                    </style>
                </head>
                <body>
                    <div class="app-container">
                        <div id="loading-message" class="loading">
                            <h2>Smart Product Advisor</h2>
                            <p>Loading your product recommendations...</p>
                        </div>
                        <div id="app-content">
                            <h1>Smart Product Advisor</h1>
                            <p>Let's find the perfect products for your customers!</p>
                            
                            <form id="recommendation-form" action="/api/recommendations" method="POST">
                                <div class="form-group">
                                    <label for="price-range">Price Range</label>
                                    <select id="price-range" name="price_range">
                                        <option value="any">Any</option>
                                        <option value="0-50">$0 - $50</option>
                                        <option value="50-100">$50 - $100</option>
                                        <option value="100-200">$100 - $200</option>
                                        <option value="200+">$200+</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label for="category">Category</label>
                                    <select id="category" name="category">
                                        <option value="any">Any</option>
                                        <option value="clothing">Clothing</option>
                                        <option value="accessories">Accessories</option>
                                        <option value="electronics">Electronics</option>
                                        <option value="home">Home & Living</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label>Keywords</label>
                                    <div class="tag-input" id="keywords-container">
                                        <input type="text" id="keyword-input" placeholder="Type and press Enter" style="border: none; outline: none; flex: 1;">
                                    </div>
                                    <input type="hidden" name="keywords" id="keywords-hidden">
                                </div>
                            </form>
                        </div>
                        <p id="error-message" class="error-message"></p>
                    </div>
                    
                    <script>
                        // Handle keywords input
                        const keywordsContainer = document.getElementById('keywords-container');
                        const keywordInput = document.getElementById('keyword-input');
                        const keywordsHidden = document.getElementById('keywords-hidden');
                        const keywords = new Set();
                        
                        function updateKeywordsHidden() {
                            keywordsHidden.value = Array.from(keywords).join(',');
                        }
                        
                        function addKeyword(keyword) {
                            if (keyword && !keywords.has(keyword)) {
                                keywords.add(keyword);
                                const tag = document.createElement('div');
                                tag.className = 'tag';
                                tag.innerHTML = `
                                    ${keyword}
                                    <button type="button" onclick="removeKeyword('${keyword}')">×</button>
                                `;
                                keywordsContainer.insertBefore(tag, keywordInput);
                                updateKeywordsHidden();
                            }
                        }
                        
                        function removeKeyword(keyword) {
                            keywords.delete(keyword);
                            const tags = keywordsContainer.getElementsByClassName('tag');
                            for (let tag of tags) {
                                if (tag.textContent.trim().replace('×', '') === keyword) {
                                    tag.remove();
                                    break;
                                }
                            }
                            updateKeywordsHidden();
                        }
                        
                        keywordInput.addEventListener('keydown', function(e) {
                            if (e.key === 'Enter') {
                                e.preventDefault();
                                const keyword = this.value.trim();
                                if (keyword) {
                                    addKeyword(keyword);
                                    this.value = '';
                                }
                            }
                        });
                    </script>
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
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port) 