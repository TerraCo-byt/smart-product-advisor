import os
import sys
import logging
import traceback
from flask import Flask, request, jsonify, redirect, session, Response
from flask_cors import CORS
import shopify
from shopify import ApiVersion
import hmac
import hashlib
import base64
import json
from urllib.parse import urlencode, quote
import re

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

# Configure session
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None',
    PERMANENT_SESSION_LIFETIME=3600
)

# Allow all origins for CORS
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": "*",
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "OPTIONS"]
    }
})

@app.after_request
def after_request(response):
    """Ensure proper headers for session cookies"""
    if 'Set-Cookie' in response.headers:
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
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

@app.route('/install')
def install():
    """
    Initial route for app installation
    """
    try:
        shop = request.args.get('shop')
        if not shop:
            logger.error("Missing shop parameter")
            return jsonify({"error": "Missing shop parameter"}), 400

        logger.info(f"Installation requested for shop: {shop}")
        logger.info(f"Request headers: {dict(request.headers)}")
        logger.info(f"Request args: {dict(request.args)}")

        # Verify HMAC if present
        if 'hmac' in request.args and not verify_hmac(request.args.to_dict()):
            logger.error("Invalid HMAC signature")
            return jsonify({"error": "Invalid HMAC signature"}), 400

        # Clear any existing sessions
        session.clear()
        
        # Generate a nonce for state validation
        state = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Store shop and state in session
        session['shop'] = shop
        session['state'] = state
        
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
        return jsonify({"error": "No valid API version found"}), 500
        
    except Exception as e:
        logger.error(f"Installation error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/app')
def app_page():
    """
    Main app page that loads in the Shopify Admin
    """
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
            return f"""
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Smart Product Advisor</title>
                    <script src="https://unpkg.com/@shopify/app-bridge@3"></script>
                    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                    <script>
                        var AppBridge = window['app-bridge'];
                        var createApp = AppBridge.default;
                        var app = createApp({{
                            apiKey: '{SHOPIFY_API_KEY}',
                            host: window.location.search.substring(1).split('=')[1],
                            forceRedirect: true
                        }});

                        function getRecommendations() {{
                            const priceRange = document.getElementById('priceRange').value;
                            const category = document.getElementById('category').value;
                            const preferences = document.getElementById('preferences').value;

                            // Show loading state
                            document.getElementById('recommendationsLoading').classList.remove('hidden');
                            document.getElementById('recommendationsList').classList.add('hidden');

                            // Make API call to get recommendations
                            fetch('/api/recommendations', {{
                                method: 'POST',
                                headers: {{
                                    'Content-Type': 'application/json',
                                }},
                                body: JSON.stringify({{
                                    price_range: priceRange,
                                    category: category,
                                    preferences: preferences,
                                    shop: '{shop}'
                                }})
                            }})
                            .then(response => response.json())
                            .then(data => {{
                                // Hide loading state
                                document.getElementById('recommendationsLoading').classList.add('hidden');
                                document.getElementById('recommendationsList').classList.remove('hidden');

                                // Display recommendations
                                const recommendationsList = document.getElementById('recommendationsList');
                                recommendationsList.innerHTML = '';

                                data.recommendations.forEach(product => {{
                                    const card = `
                                        <div class="bg-white rounded-lg shadow-md p-6 mb-4">
                                            <img src="${{product.image}}" alt="${{product.title}}" class="w-full h-48 object-cover mb-4 rounded">
                                            <h3 class="text-lg font-semibold mb-2">${{product.title}}</h3>
                                            <p class="text-gray-600 mb-2">${{product.price}}</p>
                                            <p class="text-sm text-gray-500 mb-4">${{product.description}}</p>
                                            <a href="${{product.url}}" target="_blank" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">View Product</a>
                                        </div>
                                    `;
                                    recommendationsList.innerHTML += card;
                                }});
                            }})
                            .catch(error => {{
                                console.error('Error:', error);
                                document.getElementById('recommendationsLoading').classList.add('hidden');
                                alert('Error getting recommendations. Please try again.');
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
                                        <option value="0-50">Under $50</option>
                                        <option value="50-100">$50 - $100</option>
                                        <option value="100-200">$100 - $200</option>
                                        <option value="200-500">$200 - $500</option>
                                        <option value="500+">$500+</option>
                                    </select>
                                </div>
                                
                                <div>
                                    <label class="block text-gray-700 mb-2">Category</label>
                                    <input type="text" id="category" class="w-full p-2 border rounded" placeholder="e.g., Electronics, Clothing">
                                </div>
                                
                                <div>
                                    <label class="block text-gray-700 mb-2">Customer Preferences</label>
                                    <textarea id="preferences" class="w-full p-2 border rounded" rows="3" placeholder="Describe what you're looking for (e.g., durable, waterproof, comfortable)"></textarea>
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
                </body>
            </html>
            """
        except Exception as e:
            logger.error(f"Failed to verify shop access: {str(e)}")
            return redirect(f"/install?shop={shop}")
            
    except Exception as e:
        logger.error(f"App page error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    finally:
        shopify.ShopifyResource.clear_session()

@app.route('/api/recommendations', methods=['POST'])
def get_recommendations():
    """
    API endpoint to get product recommendations
    """
    try:
        data = request.json
        shop = data.get('shop')
        price_range = data.get('price_range')
        category = data.get('category')
        preferences = data.get('preferences')

        logger.info(f"Getting recommendations for shop: {shop}")
        logger.info(f"Criteria - Price: {price_range}, Category: {category}, Preferences: {preferences}")

        # Setup Shopify session
        access_token = session.get('access_token')
        api_version = session.get('api_version', API_VERSION)
        
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, api_version)
        shopify_session.token = access_token
        shopify.ShopifyResource.activate_session(shopify_session)

        # Get products based on criteria
        query = f"status:active"
        if category:
            query += f" product_type:{category}"

        products = shopify.Product.find(limit=10)
        
        # Process and filter products
        recommendations = []
        for product in products:
            # Get the default variant price
            variant = product.variants[0]
            price = float(variant.price)
            
            # Check price range
            if price_range == "0-50" and price > 50:
                continue
            elif price_range == "50-100" and (price < 50 or price > 100):
                continue
            elif price_range == "100-200" and (price < 100 or price > 200):
                continue
            elif price_range == "200-500" and (price < 200 or price > 500):
                continue
            elif price_range == "500+" and price < 500:
                continue

            # Add to recommendations
            recommendations.append({
                'title': product.title,
                'price': f"${price:.2f}",
                'description': product.body_html[:200] + "..." if product.body_html else "",
                'image': product.images[0].src if product.images else "",
                'url': f"https://{shop}/products/{product.handle}"
            })

        return jsonify({
            'success': True,
            'recommendations': recommendations[:6]  # Limit to 6 recommendations
        })

    except Exception as e:
        logger.error(f"Recommendations error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        shopify.ShopifyResource.clear_session()

@app.route('/api/mistral/recommend', methods=['POST', 'OPTIONS'])
def get_mistral_recommendations():
    """
    API endpoint to get AI-powered product recommendations using Mistral
    """
    if request.method == 'OPTIONS':
        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Methods'] = 'POST'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Shop-Domain'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    try:
        data = request.json
        shop_domain = request.headers.get('X-Shop-Domain')
        if not shop_domain:
            return jsonify({'error': 'Missing shop domain'}), 400

        logger.info(f"Getting Mistral recommendations for shop: {shop_domain}")
        logger.info(f"Request data: {data}")

        # Get all products
        try:
            products = shopify.Product.find(limit=20)
        except Exception as e:
            logger.error(f"Error fetching products: {str(e)}")
            # Initialize Shopify session
            shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
            shopify_session = shopify.Session(shop_domain, API_VERSION)
            shopify_session.token = session.get('access_token')
            shopify.ShopifyResource.activate_session(shopify_session)
            products = shopify.Product.find(limit=20)
        
        # Extract user preferences
        preferences = data.get('preferences', {})
        price_range = preferences.get('price_range')
        category = preferences.get('category', '').lower()
        keywords = preferences.get('keywords', [])
        
        # Filter products based on price range
        filtered_products = []
        for product in products:
            if not product.variants or not product.variants[0].price:
                continue

            variant = product.variants[0]
            price = float(variant.price)
            
            # Price range filtering
            if price_range:
                min_price, max_price = map(lambda x: float(x) if x != '+' else float('inf'), 
                                        price_range.split('-'))
                if not (min_price <= price <= max_price):
                    continue
            
            # Category filtering
            if category and category not in product.product_type.lower():
                continue
                
            filtered_products.append(product)

        # Get recommendations
        recommendations = []
        for product in filtered_products[:6]:  # Limit to top 6 products
            # Generate personalized explanation using product details and user preferences
            explanation = generate_product_explanation(product, keywords, price_range)
            
            # Calculate confidence score based on matching criteria
            confidence_score = calculate_confidence_score(product, preferences)
            
            recommendations.append({
                'product': {
                    'title': product.title,
                    'price': float(product.variants[0].price),
                    'image_url': product.images[0].src if product.images else None,
                    'url': f"https://{shop_domain}/products/{product.handle}"
                },
                'confidence_score': confidence_score,
                'explanation': explanation
            })

        # Sort by confidence score
        recommendations.sort(key=lambda x: x['confidence_score'], reverse=True)

        response = jsonify({
            'success': True,
            'recommendations': recommendations
        })
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    except Exception as e:
        logger.error(f"Mistral recommendations error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        shopify.ShopifyResource.clear_session()

def generate_product_explanation(product, keywords, price_range):
    """Generate a personalized explanation for why this product matches the user's preferences"""
    reasons = []
    
    # Price-based reason
    price = float(product.variants[0].price)
    if price_range:
        min_price, max_price = map(lambda x: float(x) if x != '+' else float('inf'), 
                                price_range.split('-'))
        if price <= min_price:
            reasons.append(f"Great value: This product is within your budget at £{price:.2f}")
        elif price <= max_price:
            reasons.append(f"Good price point: Fits your budget range at £{price:.2f}")
    
    # Keyword matching with detailed explanations
    if keywords:
        matching_features = []
        for keyword in keywords:
            keyword = keyword.lower().strip()
            if not keyword:
                continue
                
            if keyword in product.title.lower():
                matching_features.append(f"Features {keyword} design")
            elif keyword in product.product_type.lower():
                matching_features.append(f"Matches your {keyword} preference")
            elif any(keyword in tag.lower() for tag in product.tags):
                matching_features.append(f"Tagged as {keyword}")
            elif keyword in product.body_html.lower():
                matching_features.append(f"Includes {keyword} features")
        
        if matching_features:
            reasons.append("Matches your preferences: " + ", ".join(matching_features))
    
    # Product type match with context
    if product.product_type:
        reasons.append(f"Perfect category match: {product.product_type}")
    
    # Extract and add key product features
    if product.body_html:
        features = extract_key_features(product.body_html)
        if features:
            reasons.append(f"Standout features: {features}")
    
    # Add product-specific highlights
    if product.tags:
        relevant_tags = [tag for tag in product.tags if any(
            keyword.lower() in tag.lower() 
            for keyword in keywords
        )] if keywords else []
        
        if relevant_tags:
            reasons.append(f"Matching qualities: {', '.join(relevant_tags)}")
    
    return "\n".join(reasons)

def extract_key_features(description):
    """Extract key features from product description"""
    # Remove HTML tags
    clean_desc = re.sub(r'<[^>]+>', '', description)
    
    # Extract sentences containing feature indicators
    feature_indicators = ['features', 'includes', 'made with', 'perfect for', 'ideal for', 'designed for']
    features = []
    
    sentences = clean_desc.split('.')
    for sentence in sentences:
        if any(indicator in sentence.lower() for indicator in feature_indicators):
            features.append(sentence.strip())
    
    return '; '.join(features[:2])  # Return top 2 feature sentences

def calculate_confidence_score(product, preferences):
    """Calculate a confidence score for how well the product matches preferences"""
    score = 0.5  # Base score
    
    # Price range match (30% weight)
    if preferences.get('price_range'):
        price = float(product.variants[0].price)
        min_price, max_price = map(lambda x: float(x) if x != '+' else float('inf'), 
                                preferences['price_range'].split('-'))
        if min_price <= price <= max_price:
            price_match = 1.0
            # Bonus for being in the middle of the range
            price_range_mid = (min_price + max_price) / 2 if max_price != float('inf') else min_price * 1.5
            price_distance = abs(price - price_range_mid) / price_range_mid
            price_match -= min(0.5, price_distance)  # Reduce score based on distance from middle
            score += price_match * 0.3
    
    # Category match (30% weight)
    if preferences.get('category'):
        category = preferences['category'].lower()
        product_type = product.product_type.lower()
        if category == product_type:
            score += 0.3
        elif category in product_type or product_type in category:
            score += 0.15
        # Check tags for category matches
        elif any(category in tag.lower() for tag in product.tags):
            score += 0.1
    
    # Keyword matches (40% weight)
    if preferences.get('keywords'):
        product_text = (
            f"{product.title} {product.body_html} {product.product_type} {' '.join(product.tags)}"
        ).lower()
        
        keyword_scores = []
        for keyword in preferences['keywords']:
            keyword = keyword.lower().strip()
            if not keyword:
                continue
                
            # Exact match in title (highest weight)
            if keyword in product.title.lower():
                keyword_scores.append(1.0)
            # Match in product type
            elif keyword in product.product_type.lower():
                keyword_scores.append(0.8)
            # Match in tags
            elif any(keyword in tag.lower() for tag in product.tags):
                keyword_scores.append(0.7)
            # Match in description
            elif keyword in product.body_html.lower():
                keyword_scores.append(0.6)
            else:
                # Check for partial matches
                partial_matches = [
                    word for word in product_text.split()
                    if keyword in word or word in keyword
                ]
                if partial_matches:
                    keyword_scores.append(0.3)
                else:
                    keyword_scores.append(0)
        
        # Average keyword scores and apply weight
        if keyword_scores:
            keyword_score = sum(keyword_scores) / len(keyword_scores)
            score += keyword_score * 0.4
    
    return min(1.0, score)  # Cap at 1.0

@app.route('/auth/callback')
def callback():
    """
    Handle OAuth callback from Shopify
    """
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
            logger.error(f"Invalid state parameter. Received: {state}, Stored: {stored_state}")
            return jsonify({"error": "Invalid state"}), 403
            
        # Verify shop
        stored_shop = session.get('shop')
        if not stored_shop or stored_shop != shop:
            logger.error(f"Shop verification failed. Received: {shop}, Stored: {stored_shop}")
            return jsonify({"error": "Invalid shop"}), 403

        # Get the working API version from session
        api_version = session.get('api_version', API_VERSION)
        logger.info(f"Using API version for callback: {api_version}")
        
        # Setup Shopify session
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        shopify_session = shopify.Session(shop, api_version)
        
        # Request access token
        access_token = shopify_session.request_token(request.args)
        if not access_token:
            logger.error("Could not get access token")
            return jsonify({"error": "Could not get access token"}), 403
            
        logger.info("Successfully obtained access token")
            
        # Store token in session
        session['access_token'] = access_token
        
        # Activate Shopify session
        shopify_session.token = access_token
        shopify.ShopifyResource.activate_session(shopify_session)
        
        try:
            # Verify the token works by making a simple API call
            shop = shopify.Shop.current()
            logger.info(f"Successfully authenticated shop: {shop.name}")
        except Exception as e:
            logger.error(f"Failed to verify shop access: {str(e)}")
            return jsonify({"error": "Failed to verify shop access"}), 500
        
        # Redirect to app page instead of admin URL
        app_url = f"{APP_URL}/app?shop={shop.myshopify_domain}"
        logger.info(f"Redirecting to app page: {app_url}")
        return redirect(app_url)
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    finally:
        shopify.ShopifyResource.clear_session()

@app.route('/')
def home():
    """
    Home route - redirects to install if shop parameter is present
    """
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
    """
    Debug route to check configuration and session state
    """
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
    app.run(host='0.0.0.0', port=port) 