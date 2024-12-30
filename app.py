import os
import sys
import logging
import traceback
from flask import Flask, request, jsonify, redirect, session, Response, make_response
from flask_cors import CORS
import shopify
from shopify import ApiVersion
import hmac
import hashlib
import base64
import json
from urllib.parse import urlencode, quote
import re
import requests
import datetime
from flask_session import Session

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(32))

# Configure session with more robust settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None',  # Required for embedded apps
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=1),
    SESSION_COOKIE_NAME='sp_session',
    SESSION_COOKIE_DOMAIN=None,  # Allow dynamic domain setting
    SESSION_REFRESH_EACH_REQUEST=True,
)

# Custom session interface to handle embedded app requirements
class ShopifySessionInterface(SessionInterface):
    def open_session(self, app, request):
        sid = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
        if not sid:
            sid = base64.b64encode(os.urandom(32)).decode('utf-8')
        shop = request.args.get('shop', '')
        s = Session()
        s.sid = sid
        s.shop = shop
        s.permanent = True
        return s

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        
        # Always set SameSite=None for embedded apps
        if not session:
            response.delete_cookie(
                app.config['SESSION_COOKIE_NAME'],
                domain=domain,
                path=path
            )
            return

        if isinstance(response, Response):
            http_only = app.config['SESSION_COOKIE_HTTPONLY']
            secure = app.config['SESSION_COOKIE_SECURE']
            expires = self.get_expiration_time(app, session)
            
            # Set cookie with proper flags
            response.set_cookie(
                app.config['SESSION_COOKIE_NAME'],
                session.sid,
                expires=expires,
                httponly=http_only,
                domain=domain,
                path=path,
                secure=secure,
                samesite='None'  # Required for embedded apps
            )

# Use custom session interface
app.session_interface = ShopifySessionInterface()

# Allow all origins for CORS with proper configuration
CORS(app, resources={
    r"/*": {
        "origins": ["https://*.myshopify.com", "https://admin.shopify.com", "https://partners.shopify.com"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-Shop-Domain", "Authorization", "Origin", "Cookie"],
        "supports_credentials": True,
        "expose_headers": ["Set-Cookie", "Content-Range", "X-Content-Range"]
    }
})

@app.after_request
def after_request(response):
    """Ensure proper headers for session cookies and CORS"""
    origin = request.headers.get('Origin', '')
    shop_domain = request.args.get('shop', request.headers.get('X-Shop-Domain', ''))
    
    if origin and ('.myshopify.com' in origin or 'admin.shopify.com' in origin or 'partners.shopify.com' in origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Shop-Domain, Authorization, Origin, Cookie'
        response.headers['Access-Control-Expose-Headers'] = 'Set-Cookie'
        
        # Handle cookies
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.getlist('Set-Cookie')
            response.headers.remove('Set-Cookie')
            for cookie in cookies:
                if 'SameSite=' not in cookie:
                    cookie += '; SameSite=None; Secure'
                if 'Secure' not in cookie:
                    cookie += '; Secure'
                response.headers.add('Set-Cookie', cookie)
                
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'ALLOWALL'  # Required for embedded apps
        response.headers['Content-Security-Policy'] = "frame-ancestors 'self' https://*.myshopify.com https://admin.shopify.com;"
        
    return response

# Configuration
SHOPIFY_API_KEY = os.environ.get('SHOPIFY_API_KEY')
SHOPIFY_API_SECRET = os.environ.get('SHOPIFY_API_SECRET')
APP_URL = os.environ.get('RENDER_EXTERNAL_URL')
if not APP_URL:
    logger.error("RENDER_EXTERNAL_URL not set!")
    APP_URL = os.environ.get('APP_URL', 'http://localhost:8000')
logger.info(f"Using APP_URL: {APP_URL}")

SCOPES = ['read_products', 'write_products', 'read_themes', 'write_themes']

# Set API Version
AVAILABLE_VERSIONS = [
    '2023-07',
    '2023-04',
    '2023-01'
]

# Use the most recent version
API_VERSION = AVAILABLE_VERSIONS[0]
logger.info(f"Using Shopify API version: {API_VERSION}")
logger.info(f"Available API versions: {AVAILABLE_VERSIONS}")

# Validate configuration
if not SHOPIFY_API_KEY or not SHOPIFY_API_SECRET:
    logger.error("Missing Shopify API credentials!")
    raise ValueError("Missing required environment variables: SHOPIFY_API_KEY and SHOPIFY_API_SECRET")

# Hugging Face configuration
HUGGINGFACE_API_TOKEN = os.environ.get('HUGGINGFACE_API_TOKEN')
if not HUGGINGFACE_API_TOKEN:
    logger.error("Missing Hugging Face API token!")
    raise ValueError("Missing required environment variable: HUGGINGFACE_API_TOKEN")

HUGGINGFACE_API_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2"

def verify_hmac(params):
    """Verify the HMAC signature from Shopify"""
    try:
        hmac_value = params.get('hmac')
        if not hmac_value:
            return False
            
        params_copy = params.copy()
        params_copy.pop('hmac', None)
        
        # Sort and combine parameters
        sorted_params = '&'.join([
            f"{key}={value}"
            for key, value in sorted(params_copy.items())
        ])
        
        digest = hmac.new(
            SHOPIFY_API_SECRET.encode('utf-8'),
            sorted_params.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(digest.encode('utf-8'), hmac_value.encode('utf-8'))
    except Exception as e:
        logger.error(f"HMAC verification error: {str(e)}")
        return False

def generate_product_recommendations(products, preferences):
    """Generate AI-powered product recommendations using Hugging Face Inference API"""
    try:
        logger.info("Starting recommendation generation...")
        logger.info(f"Number of products to analyze: {len(products)}")
        logger.info(f"User preferences: {preferences}")

        # Prepare product context
        product_context = "\n".join([
            f"Product {i+1}:"
            f"\nTitle: {p.title}"
            f"\nType: {p.product_type}"
            f"\nPrice: £{p.variants[0].price}"
            f"\nDescription: {p.body_html}"
            f"\nTags: {', '.join(p.tags)}"
            for i, p in enumerate(products)
        ])

        # Prepare user preferences
        user_prefs = (
            f"Price Range: {preferences.get('price_range', 'Any')}\n"
            f"Category: {preferences.get('category', 'Any')}\n"
            f"Keywords: {', '.join(preferences.get('keywords', []))}"
        )

        logger.info("Prepared context and preferences")

        # Construct the prompt
        system_prompt = """You are a smart product recommendation system. Based on the available products and user preferences, recommend the most suitable products. For each recommendation:
1. Check if the product matches the price range and category
2. Evaluate how well it matches the user's keywords and preferences
3. Provide a clear explanation of why this product is recommended
4. Give a confidence score between 0 and 1

Return your response as a JSON array with this structure:
[{
    "product_index": (number starting from 1),
    "confidence_score": (number between 0 and 1),
    "explanation": "Clear explanation of why this product matches"
}]"""

        user_prompt = f"""Available Products:
{product_context}

User Preferences:
{user_prefs}

Provide the best product recommendations as a JSON array."""

        logger.info("Constructed prompts")

        # Prepare the payload for Hugging Face
        payload = {
            "inputs": f"{system_prompt}\n\n{user_prompt}",
            "parameters": {
                "max_new_tokens": 1000,
                "temperature": 0.7,
                "return_full_text": False
            }
        }

        # Make request to Hugging Face
        headers = {
            "Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}",
            "Content-Type": "application/json"
        }

        logger.info("Making request to Hugging Face API...")
        response = requests.post(
            HUGGINGFACE_API_URL,
            headers=headers,
            json=payload,
            timeout=30  # Add timeout
        )

        logger.info(f"Hugging Face API response status: {response.status_code}")
        logger.info(f"Hugging Face API response: {response.text[:500]}...")  # Log first 500 chars

        if response.status_code != 200:
            logger.error(f"Hugging Face API error: {response.text}")
            raise Exception(f"Failed to get recommendations from Hugging Face: {response.text}")

        # Parse response
        response_data = response.json()
        if not response_data or not isinstance(response_data, list) or not response_data[0].get("generated_text"):
            logger.error(f"Invalid response format from Hugging Face: {response_data}")
            raise Exception("Invalid response format from Hugging Face")

        recommendations_text = response_data[0]["generated_text"]
        logger.info(f"Raw recommendations text: {recommendations_text[:500]}...")

        # Extract JSON array from response
        json_str = recommendations_text.strip()
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0]
        elif "```" in json_str:
            json_str = json_str.split("```")[1]

        logger.info(f"Extracted JSON string: {json_str}")

        try:
            recommendations_data = json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse recommendations JSON: {e}")
            logger.error(f"JSON string was: {json_str}")
            raise Exception("Failed to parse recommendations response")

        logger.info(f"Parsed recommendations data: {recommendations_data}")

        # Format recommendations
        formatted_recommendations = []
        for rec in recommendations_data:
            product_idx = rec['product_index'] - 1
            if 0 <= product_idx < len(products):
                product = products[product_idx]
                formatted_rec = {
                    'product': {
                        'title': product.title,
                        'price': float(product.variants[0].price),
                        'image_url': product.images[0].src if product.images else None,
                        'url': f"https://{request.headers.get('X-Shop-Domain')}/products/{product.handle}"
                    },
                    'confidence_score': float(rec['confidence_score']),
                    'explanation': rec['explanation']
                }
                formatted_recommendations.append(formatted_rec)
                logger.info(f"Added recommendation for product: {product.title}")

        logger.info(f"Final formatted recommendations count: {len(formatted_recommendations)}")
        return formatted_recommendations

    except Exception as e:
        logger.error(f"Error generating recommendations: {str(e)}")
        logger.error(traceback.format_exc())
        raise

@app.route('/api/recommendations', methods=['POST', 'OPTIONS'])
def get_recommendations():
    """API endpoint to get AI-powered product recommendations"""
    if request.method == 'OPTIONS':
        # Handle preflight request
        response = Response()
        origin = request.headers.get('Origin', '')
        if origin and ('.myshopify.com' in origin or 'admin.shopify.com' in origin or 'partners.shopify.com' in origin):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Shop-Domain, Authorization, Origin'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Max-Age'] = '3600'
        return response

    try:
        # Log request details
        logger.info("=== New Recommendation Request ===")
        logger.info(f"Headers: {dict(request.headers)}")
        logger.info(f"Request data: {request.get_data(as_text=True)}")
        logger.info(f"Session data: {dict(session)}")
        
        # Validate request
        if not request.is_json:
            logger.error("Request must be JSON")
            return jsonify({
                'success': False,
                'error': 'Request must be JSON'
            }), 400
        
        data = request.json
        if not data:
            logger.error("Empty request body")
            return jsonify({
                'success': False,
                'error': 'Empty request body'
            }), 400

        shop_domain = request.headers.get('X-Shop-Domain')
        if not shop_domain:
            logger.error("Missing shop domain header")
            return jsonify({
                'success': False,
                'error': 'Missing shop domain header'
            }), 400

        logger.info(f"Getting recommendations for shop: {shop_domain}")

        # Get all products
        try:
            # Initialize Shopify session
            logger.info("Setting up Shopify session...")
            shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
            shopify_session = shopify.Session(shop_domain, API_VERSION)
            
            # Try to get access token from session
            access_token = session.get('access_token')
            if not access_token:
                logger.warning("No access token in session, redirecting to install")
                install_url = f"{APP_URL}/install?shop={shop_domain}"
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'redirect_url': install_url
                }), 401
            
            logger.info("Using access token from session")
            shopify_session.token = access_token
            shopify.ShopifyResource.activate_session(shopify_session)
            
            # Verify session is valid
            try:
                shop = shopify.Shop.current()
                logger.info(f"Successfully verified shop access: {shop.name}")
            except Exception as e:
                logger.error(f"Invalid session, redirecting to install: {str(e)}")
                install_url = f"{APP_URL}/install?shop={shop_domain}"
                return jsonify({
                    'success': False,
                    'error': 'Invalid session',
                    'redirect_url': install_url
                }), 401
            
            logger.info("Fetching products...")
            products = shopify.Product.find(limit=20)
            if not products:
                logger.warning("No products found in shop")
                return jsonify({
                    'success': False,
                    'error': 'No products found in shop'
                }), 404
                
            logger.info(f"Found {len(products)} products")
            
        except Exception as e:
            logger.error(f"Error fetching products: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'success': False,
                'error': f'Failed to fetch products: {str(e)}'
            }), 500
        
        # Extract user preferences
        preferences = data.get('preferences', {})
        if not preferences:
            logger.error("No preferences provided")
            return jsonify({
                'success': False,
                'error': 'No preferences provided'
            }), 400
            
        logger.info(f"User preferences: {preferences}")
        
        # Get AI-powered recommendations
        try:
            logger.info("Generating recommendations...")
            recommendations = generate_product_recommendations(products, preferences)
            if not recommendations:
                logger.warning("No recommendations generated")
                return jsonify({
                    'success': False,
                    'error': 'No suitable recommendations found'
                }), 404
                
            logger.info(f"Generated {len(recommendations)} recommendations")
            
            # Sort by confidence score
            recommendations.sort(key=lambda x: x['confidence_score'], reverse=True)
            recommendations = recommendations[:6]  # Limit to top 6 recommendations
            
            logger.info("Successfully processed recommendations")
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'success': False,
                'error': f'Failed to generate recommendations: {str(e)}'
            }), 500

        response = jsonify({
            'success': True,
            'recommendations': recommendations
        })
        
        # Set CORS headers for the response
        origin = request.headers.get('Origin', '')
        if origin and ('.myshopify.com' in origin or 'admin.shopify.com' in origin or 'partners.shopify.com' in origin):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        return response

    except Exception as e:
        logger.error("=== Recommendation Request Failed ===")
        logger.error(f"Error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        try:
            shopify.ShopifyResource.clear_session()
        except Exception as e:
            logger.error(f"Error clearing session: {str(e)}")

@app.route('/auth/callback')
def callback():
    """Handle OAuth callback from Shopify"""
    try:
        shop = request.args.get('shop')
        if not shop:
            logger.error("Missing shop parameter in callback")
            return jsonify({"error": "Missing shop parameter"}), 400
            
        logger.info(f"Callback received for shop: {shop}")
        logger.info(f"Callback headers: {dict(request.headers)}")
        logger.info(f"Callback args: {dict(request.args)}")
            
        # Verify state
        state = request.args.get('state')
        stored_state = session.get('state')
        if not state or not stored_state or state != stored_state:
            logger.warning(f"State mismatch or missing. Received: {state}, Stored: {stored_state}")
            # Continue anyway since we have the shop parameter
            logger.info("Proceeding with authentication despite state mismatch")
            
        # Get the working API version from session or use default
        api_version = session.get('api_version', API_VERSION)
        logger.info(f"Using API version for callback: {api_version}")
        
        # Setup Shopify session
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, api_version)
        
        # Request access token
        try:
            access_token = shopify_session.request_token(request.args)
            if not access_token:
                logger.error("Could not get access token")
                return redirect(f"/install?shop={shop}")
                
            logger.info("Successfully obtained access token")
                
            # Store token in session
            session['access_token'] = access_token
            session['shop'] = shop
            
            # Activate Shopify session
            shopify_session.token = access_token
            shopify.ShopifyResource.activate_session(shopify_session)
            
            try:
                # Verify the token works by making a simple API call
                shop_info = shopify.Shop.current()
                logger.info(f"Successfully authenticated shop: {shop_info.name}")
            except Exception as e:
                logger.error(f"Failed to verify shop access: {str(e)}")
                return redirect(f"/install?shop={shop}")
            
            # Redirect to app page
            app_url = f"{APP_URL}/app?shop={shop}"
            logger.info(f"Redirecting to app page: {app_url}")
            return redirect(app_url)
            
        except Exception as e:
            logger.error(f"Error requesting access token: {str(e)}")
            return redirect(f"/install?shop={shop}")
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(f"/install?shop={shop}")

@app.route('/install')
def install():
    """Initial route for app installation"""
    try:
        shop = request.args.get('shop')
        if not shop:
            logger.error("Missing shop parameter")
            return jsonify({"error": "Missing shop parameter"}), 400

        logger.info(f"Installation requested for shop: {shop}")
        logger.info(f"Request headers: {dict(request.headers)}")
        logger.info(f"Request args: {dict(request.args)}")

        # Clear any existing sessions
        session.clear()
        
        # Generate a nonce for state validation
        state = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Store shop and state in session
        session['shop'] = shop
        session['state'] = state
        session.permanent = True  # Make session persistent
        
        # Initialize shopify session
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        
        # Create permission URL
        redirect_uri = f"{APP_URL}/auth/callback"
        logger.info(f"Using redirect URI: {redirect_uri}")
        
        # Try each version until one works
        for version in AVAILABLE_VERSIONS:
            try:
                shopify_session = shopify.Session(shop, version)
                auth_url = shopify_session.create_permission_url(
                    SCOPES,
                    redirect_uri,
                    state
                )
                logger.info(f"Successfully created auth URL with API version {version}: {auth_url}")
                session['api_version'] = version  # Store working version
                return redirect(auth_url)
            except Exception as e:
                logger.warning(f"Failed to use API version {version}: {str(e)}")
                continue
        
        # If we get here, no versions worked
        logger.error("No valid API version found")
        return jsonify({"error": "Failed to create authorization URL"}), 500
        
    except Exception as e:
        logger.error(f"Installation error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/app')
def app_page():
    """Main app page that loads in the Shopify Admin"""
    try:
        shop = request.args.get('shop')
        if not shop:
            logger.error("Missing shop parameter in app page")
            return jsonify({"error": "Missing shop parameter"}), 400

        # Make session permanent
        session.permanent = True
        
        # Verify shop has valid access token
        access_token = session.get('access_token')
        if not access_token:
            logger.info(f"No access token found, redirecting to install: {shop}")
            return redirect(f"/install?shop={shop}")

        # Get the API version from session
        api_version = session.get('api_version', API_VERSION)
        
        # Setup Shopify session
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, api_version)
        shopify_session.token = access_token
        shopify.ShopifyResource.activate_session(shopify_session)

        try:
            # Verify the token still works
            shop_data = shopify.Shop.current()
            logger.info(f"Loading app page for shop: {shop_data.name}")
            
            # Return the app HTML
            response = make_response(f"""
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Smart Product Advisor</title>
                    <script src="https://unpkg.com/@shopify/app-bridge@3"></script>
                    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                    <script>
                        // Initialize app-bridge with embedded app requirements
                        var AppBridge = window['app-bridge'];
                        var createApp = AppBridge.default;
                        var actions = AppBridge.actions;
                        var app = createApp({{
                            apiKey: '{SHOPIFY_API_KEY}',
                            host: window.location.search.substring(1).split('=')[1],
                            forceRedirect: true
                        }});

                        // Set up app-bridge actions
                        var TitleBar = actions.TitleBar;
                        var Button = actions.Button;
                        var Loading = actions.Loading;
                        var Modal = actions.Modal;
                        var Redirect = actions.Redirect;

                        // Create title bar
                        var titleBarOptions = {{
                            title: 'Smart Product Advisor',
                        }};
                        var titleBar = TitleBar.create(app, titleBarOptions);

                        // Handle session expiry
                        function handleSessionExpiry(response) {{
                            if (response.status === 401 || response.status === 403) {{
                                const redirect = Redirect.create(app);
                                redirect.dispatch(Redirect.Action.REMOTE, '/install?shop={shop}');
                                return true;
                            }}
                            return false;
                        }}

                        // Function to get CSRF token from cookies
                        function getCSRFToken() {{
                            return document.cookie.split('; ').find(row => row.startsWith('sp_session='))?.split('=')[1];
                        }}

                        function getRecommendations() {{
                            const priceRange = document.getElementById('priceRange').value;
                            const category = document.getElementById('category').value;
                            const preferences = document.getElementById('preferences').value;

                            // Show loading state using app-bridge
                            const loading = Loading.create(app);
                            loading.dispatch(Loading.Action.START);

                            // Hide previous recommendations
                            document.getElementById('recommendationsList').classList.add('hidden');

                            // Make API call to get recommendations
                            fetch('{APP_URL}/api/recommendations', {{
                                method: 'POST',
                                headers: {{
                                    'Content-Type': 'application/json',
                                    'X-Shop-Domain': '{shop}',
                                    'X-CSRF-Token': getCSRFToken()
                                }},
                                credentials: 'include',
                                body: JSON.stringify({{
                                    preferences: {{
                                        price_range: priceRange,
                                        category: category,
                                        keywords: preferences.split(',').map(k => k.trim())
                                    }}
                                }})
                            }})
                            .then(response => {{
                                if (handleSessionExpiry(response)) {{
                                    throw new Error('Session expired');
                                }}
                                if (!response.ok) {{
                                    return response.json().then(data => {{
                                        throw new Error(data.error || `HTTP error! status: ${{response.status}}`);
                                    }});
                                }}
                                return response.json();
                            }})
                            .then(data => {{
                                // Stop loading state
                                loading.dispatch(Loading.Action.STOP);

                                if (!data.success) {{
                                    throw new Error(data.error || 'Failed to get recommendations');
                                }}

                                // Display recommendations
                                const recommendationsList = document.getElementById('recommendationsList');
                                recommendationsList.innerHTML = '';
                                recommendationsList.classList.remove('hidden');

                                data.recommendations.forEach(rec => {{
                                    const product = rec.product;
                                    const card = `
                                        <div class="bg-white rounded-lg shadow-md p-6 mb-4">
                                            ${{product.image_url ? `<img src="${{product.image_url}}" alt="${{product.title}}" class="w-full h-48 object-cover mb-4 rounded">` : ''}}
                                            <h3 class="text-lg font-semibold mb-2">${{product.title}}</h3>
                                            <p class="text-gray-600 mb-2">£${{product.price.toFixed(2)}}</p>
                                            <div class="mb-4">
                                                <div class="text-sm text-gray-500">Confidence Score: ${{(rec.confidence_score * 100).toFixed(1)}}%</div>
                                                <div class="text-sm text-gray-700 mt-2">${{rec.explanation}}</div>
                                            </div>
                                            <a href="${{product.url}}" target="_blank" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">View Product</a>
                                        </div>
                                    `;
                                    recommendationsList.innerHTML += card;
                                }});
                            }})
                            .catch(error => {{
                                // Stop loading state
                                loading.dispatch(Loading.Action.STOP);

                                console.error('Error:', error);
                                if (!error.message.includes('Session expired')) {{
                                    const modal = Modal.create(app, {{
                                        title: 'Error',
                                        message: `Error getting recommendations: ${{error.message}}`,
                                        primaryAction: {{
                                            content: 'OK',
                                            onAction: () => modal.dispatch(Modal.Action.CLOSE),
                                        }},
                                    }});
                                    modal.dispatch(Modal.Action.OPEN);
                                }}
                            }});
                        }}
                    </script>
                </head>
                <body class="bg-gray-100">
                    <div class="container mx-auto px-4 py-8">
                        <h1 class="text-3xl font-bold mb-8 text-gray-800">Smart Product Advisor</h1>
                        
                        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                            <h2 class="text-xl font-semibold mb-4">Get Product Recommendations</h2>
                            
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-gray-700 mb-2">Price Range</label>
                                    <select id="priceRange" class="w-full p-2 border rounded">
                                        <option value="0-50">Under £50</option>
                                        <option value="50-100">£50 - £100</option>
                                        <option value="100-200">£100 - £200</option>
                                        <option value="200-500">£200 - £500</option>
                                        <option value="500+">£500+</option>
                                    </select>
                                </div>
                                
                                <div>
                                    <label class="block text-gray-700 mb-2">Category</label>
                                    <input type="text" id="category" class="w-full p-2 border rounded" placeholder="e.g., Blankets, Pouffe">
                                </div>
                                
                                <div>
                                    <label class="block text-gray-700 mb-2">Customer Preferences</label>
                                    <textarea id="preferences" class="w-full p-2 border rounded" rows="3" placeholder="Describe what you're looking for (e.g., handmade, cotton, comfortable)"></textarea>
                                </div>
                                
                                <button onclick="getRecommendations()" class="bg-green-500 text-white px-6 py-2 rounded hover:bg-green-600">
                                    Get Recommendations
                                </button>
                            </div>
                        </div>
                        
                        <div id="recommendationsLoading" class="hidden">
                            <div class="flex items-center justify-center py-8">
                                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-green-500"></div>
                            </div>
                        </div>
                        
                        <div id="recommendationsList" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <!-- Recommendations will be inserted here -->
                        </div>
                    </div>

                    <script>
                        function getRecommendations() {{
                            const priceRange = document.getElementById('priceRange').value;
                            const category = document.getElementById('category').value;
                            const preferences = document.getElementById('preferences').value;

                            // Show loading state
                            document.getElementById('recommendationsLoading').classList.remove('hidden');
                            document.getElementById('recommendationsList').classList.add('hidden');

                            // Make API call to get recommendations
                            fetch('{APP_URL}/api/recommendations', {{
                                method: 'POST',
                                headers: {{
                                    'Content-Type': 'application/json',
                                    'X-Shop-Domain': '{shop}'
                                }},
                                credentials: 'include',
                                body: JSON.stringify({{
                                    preferences: {{
                                        price_range: priceRange,
                                        category: category,
                                        keywords: preferences.split(',').map(k => k.trim())
                                    }}
                                }})
                            }})
                            .then(response => {{
                                if (!response.ok) {{
                                    return response.json().then(data => {{
                                        if (data.redirect_url) {{
                                            // Handle authentication redirect
                                            window.location.href = data.redirect_url;
                                            throw new Error('Redirecting for authentication...');
                                        }}
                                        throw new Error(data.error || `HTTP error! status: ${{response.status}}`);
                                    }});
                                }}
                                return response.json();
                            }})
                            .then(data => {{
                                // Hide loading state
                                document.getElementById('recommendationsLoading').classList.add('hidden');
                                document.getElementById('recommendationsList').classList.remove('hidden');

                                if (!data.success) {{
                                    throw new Error(data.error || 'Failed to get recommendations');
                                }}

                                // Display recommendations
                                const recommendationsList = document.getElementById('recommendationsList');
                                recommendationsList.innerHTML = '';

                                data.recommendations.forEach(rec => {{
                                    const product = rec.product;
                                    const card = `
                                        <div class="bg-white rounded-lg shadow-md p-6 mb-4">
                                            ${{product.image_url ? `<img src="${{product.image_url}}" alt="${{product.title}}" class="w-full h-48 object-cover mb-4 rounded">` : ''}}
                                            <h3 class="text-lg font-semibold mb-2">${{product.title}}</h3>
                                            <p class="text-gray-600 mb-2">£${{product.price.toFixed(2)}}</p>
                                            <div class="mb-4">
                                                <div class="text-sm text-gray-500">Confidence Score: ${(rec.confidence_score * 100).toFixed(1)}%</div>
                                                <div class="text-sm text-gray-700 mt-2">${{rec.explanation}}</div>
                                            </div>
                                            <a href="${{product.url}}" target="_blank" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">View Product</a>
                                        </div>
                                    `;
                                    recommendationsList.innerHTML += card;
                                }});
                            }})
                            .catch(error => {{
                                console.error('Error:', error);
                                document.getElementById('recommendationsLoading').classList.add('hidden');
                                if (!error.message.includes('Redirecting')) {{
                                    alert('Error getting recommendations: ' + error.message);
                                }}
                            }});
                        }}
                    </script>
                </body>
            </html>
            """)
            
            # Set cookie headers for embedded app
            response.headers['Cache-Control'] = 'no-store'
            cookie = f'sp_session={session.sid}; Path=/; HttpOnly; Secure; SameSite=None'
            response.headers['Set-Cookie'] = cookie
            
            # Add security headers
            response.headers['X-Frame-Options'] = 'ALLOWALL'
            response.headers['Content-Security-Policy'] = "frame-ancestors 'self' https://*.myshopify.com https://admin.shopify.com;"
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to verify shop access: {str(e)}")
            return redirect(f"/install?shop={shop}")
            
    except Exception as e:
        logger.error(f"App page error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    finally:
        shopify.ShopifyResource.clear_session()

@app.route('/')
def home():
    """Root route - redirects to install if shop parameter is present"""
    try:
        shop = request.args.get('shop')
        if shop:
            logger.info(f"Redirecting to install for shop: {shop}")
            return redirect(f"/install?shop={shop}")
        return "Welcome to Smart Product Advisor"
    except Exception as e:
        logger.error(f"Home route error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/debug')
def debug():
    """Debug route to check configuration and session state"""
    try:
        debug_data = {
            'api_key_present': bool(SHOPIFY_API_KEY),
            'api_secret_present': bool(SHOPIFY_API_SECRET),
            'app_url': APP_URL,
            'current_api_version': API_VERSION,
            'available_versions': AVAILABLE_VERSIONS,
            'session_api_version': session.get('api_version'),
            'session': dict(session),
            'request_args': dict(request.args),
            'headers': dict(request.headers)
        }
        logger.info("Debug info requested")
        return jsonify(debug_data)
    except Exception as e:
        logger.error(f"Debug route error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Check if we can access environment variables
        if not SHOPIFY_API_KEY or not SHOPIFY_API_SECRET:
            raise ValueError("Missing required environment variables")

        # Check if we can create a session
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        
        # Check if we can access the database (if needed)
        # Add any other critical checks here
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'app_url': APP_URL,
            'api_version': API_VERSION
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"404 error: {error}")
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    logger.info(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, threaded=True) 