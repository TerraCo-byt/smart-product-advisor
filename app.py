import os
import sys
import logging
import traceback
from flask import Flask, request, jsonify, redirect, session, Response, make_response, render_template_string
from flask_cors import CORS
from flask.sessions import SessionInterface
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
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

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
    SESSION_TYPE='filesystem',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=1),
    SESSION_COOKIE_NAME='sp_session',
    SESSION_REFRESH_EACH_REQUEST=True,
)

# Initialize Flask-Session
Session(app)

# Allow all origins for CORS
CORS(app, 
     supports_credentials=True,
     resources={
        r"/*": {
            "origins": "*",
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "X-Shop-Domain", "Authorization", "Origin", "Cookie", "X-Requested-With"],
            "expose_headers": ["Set-Cookie"],
            "supports_credentials": True,
            "max_age": 3600
        }
     })

@app.before_request
def before_request():
    """Setup request context and handle CORS preflight"""
    # Handle CORS preflight requests
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", request.headers.get('Origin', '*'))
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    # Handle authentication
    shop = request.args.get('shop', request.headers.get('X-Shop-Domain'))
    if shop:
        session['shop'] = shop
        session.permanent = True

@app.after_request
def after_request(response):
    """Ensure proper headers for cookies and CORS"""
    origin = request.headers.get('Origin', '')
    
    # Allow Shopify admin and custom domains
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Shop-Domain, Authorization'
        
        # Set frame ancestors for embedded app
        response.headers['Content-Security-Policy'] = (
            "frame-ancestors https://*.myshopify.com "
            "https://admin.shopify.com "
            "https://*.shopify.com "
            "https://partners.shopify.com"
        )
        # Remove X-Frame-Options as it's not needed when CSP frame-ancestors is present
        if 'X-Frame-Options' in response.headers:
            del response.headers['X-Frame-Options']
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    
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

def verify_request(request):
    """Verify if the request is authenticated and has necessary parameters"""
    shop = request.args.get('shop')
    if not shop:
        return False, None, "Missing shop parameter"
        
    # Check if we have a valid session
    access_token = session.get('access_token')
    if not access_token:
        return False, shop, "No access token"
        
    return True, shop, None

@app.route('/app')
def app_page():
    """Main app page that loads in the Shopify Admin"""
    try:
        shop = request.args.get('shop')
        host = request.args.get('host')
        embedded = request.args.get('embedded', '1')
        
        if not shop:
            return jsonify({"error": "Missing shop parameter"}), 400

        # Check if we have a valid session for this shop
        if session.get('shop') == shop and session.get('access_token'):
            try:
                # Setup Shopify session
                shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
                shopify_session = shopify.Session(shop, API_VERSION)
                shopify_session.token = session.get('access_token')
                
                # Verify the token works
                shopify.ShopifyResource.activate_session(shopify_session)
                shop_data = shopify.Shop.current()
                
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
                                window.addEventListener('load', function() {
                                    const host = new URLSearchParams(window.location.search).get('host');
                                    if (!host) {
                                        console.error('Missing host parameter');
                                        return;
                                    }
                                    
                                    const config = {
                                        apiKey: '{{ api_key }}',
                                        host: host,
                                        forceRedirect: true
                                    };
                                    
                                    try {
                                        window.app = window.shopify.createApp(config);
                                        const actions = window.shopify.actions;
                                        const TitleBar = actions.TitleBar;
                                        TitleBar.create(window.app, {
                                            title: 'Smart Product Advisor'
                                        });
                                    } catch (error) {
                                        console.error('Error initializing app:', error);
                                    }
                                });
                            </script>
                        </head>
                        <body>
                            <div id="app">Loading Smart Product Advisor...</div>
                        </body>
                    </html>
                """, api_key=SHOPIFY_API_KEY))
                
                # Set security headers for embedding
                response.headers['Content-Security-Policy'] = (
                    "frame-ancestors https://*.myshopify.com "
                    "https://admin.shopify.com "
                    "https://*.shopify.com "
                    "https://partners.shopify.com"
                )
                # Remove X-Frame-Options as it's not needed when CSP frame-ancestors is present
                if 'X-Frame-Options' in response.headers:
                    del response.headers['X-Frame-Options']
                
                return response
                
            except Exception as e:
                logger.error(f"Failed to verify shop access: {str(e)}")
                session.clear()
        
        # No valid session, redirect to install with host parameter
        install_url = f"/install?shop={shop}"
        if host:
            install_url += f"&host={host}"
        if embedded:
            install_url += f"&embedded={embedded}"
        return redirect(install_url)
            
    except Exception as e:
        logger.error(f"App page error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    finally:
        shopify.ShopifyResource.clear_session()

@app.route('/install')
def install():
    """Initial route for app installation"""
    try:
        shop = request.args.get('shop')
        host = request.args.get('host')
        
        if not shop:
            return jsonify({"error": "Missing shop parameter"}), 400
            
        # Generate installation URL
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, API_VERSION)
        
        # Generate a nonce for state validation
        state = base64.b64encode(os.urandom(16)).decode('utf-8')
        session['state'] = state
        session['shop'] = shop
        
        # Create permission URL
        redirect_uri = f"{APP_URL}/auth/callback"
        auth_url = shopify_session.create_permission_url(
            SCOPES,
            redirect_uri,
            state
        )
        
        # Add host parameter if present
        if host:
            auth_url += f"&host={host}"
            
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Installation error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    """Root route - redirects to install if shop parameter is present"""
    try:
        shop = request.args.get('shop')
        if shop:
            logger.info(f"Redirecting to install for shop: {shop}")
            return redirect(f"/install?shop={shop}")
            
        # Return a basic HTML page for root
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

# Add a catch-all route for handling 404s
@app.route('/<path:path>')
def catch_all(path):
    """Catch-all route to handle any undefined routes"""
    shop = request.args.get('shop')
    if shop:
        logger.info(f"Redirecting undefined path to install: {path}")
        return redirect(f"/install?shop={shop}")
    return jsonify({"error": "Not found"}), 404

@app.route('/auth/callback')
def callback():
    """Handle OAuth callback from Shopify"""
    try:
        shop = request.args.get('shop')
        host = request.args.get('host')
        
        if not shop:
            return jsonify({"error": "Missing shop parameter"}), 400
            
        # Verify state
        state = request.args.get('state')
        stored_state = session.get('state')
        if not state or not stored_state or state != stored_state:
            return jsonify({"error": "Invalid state parameter"}), 400
            
        # Setup Shopify session
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, API_VERSION)
        
        try:
            # Request access token
            access_token = shopify_session.request_token(request.args)
            if not access_token:
                return redirect(f"/install?shop={shop}")
                
            # Store token in session
            session['access_token'] = access_token
            session['shop'] = shop
            
            # Redirect to app with shop and host parameters
            app_url = f"/app?shop={shop}"
            if host:
                app_url += f"&host={host}"
            return redirect(app_url)
            
        except Exception as e:
            logger.error(f"Error requesting access token: {str(e)}")
            return redirect(f"/install?shop={shop}")
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        return redirect(f"/install?shop={shop}")
    finally:
        shopify.ShopifyResource.clear_session()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    logger.info(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, threaded=True) 