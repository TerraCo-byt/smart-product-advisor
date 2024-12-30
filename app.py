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
import requests

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
        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Methods'] = 'POST'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Shop-Domain, Origin'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    try:
        # Log request details
        logger.info("=== New Recommendation Request ===")
        logger.info(f"Headers: {dict(request.headers)}")
        logger.info(f"Request data: {request.get_data(as_text=True)}")
        
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
            access_token = session.get('access_token')
            
            if not access_token:
                logger.error("No access token in session")
                return jsonify({
                    'success': False,
                    'error': 'Authentication required'
                }), 401
                
            logger.info(f"Access token from session: {access_token}")
            
            shopify_session.token = access_token
            shopify.ShopifyResource.activate_session(shopify_session)
            
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
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
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
        
        # Redirect to app page
        app_url = f"{APP_URL}/app?shop={shop.myshopify_domain}"
        logger.info(f"Redirecting to app page: {app_url}")
        return redirect(app_url)
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

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

                    <script>
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
                                    'X-Shop-Domain': '{shop}'
                                }},
                                body: JSON.stringify({{
                                    preferences: {{
                                        price_range: priceRange,
                                        category: category,
                                        keywords: preferences.split(',').map(k => k.trim())
                                    }}
                                }})
                            }})
                            .then(response => response.json())
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
                                console.error('Error:', error);
                                document.getElementById('recommendationsLoading').classList.add('hidden');
                                alert('Error getting recommendations: ' + error.message);
                            }});
                        }}
                    </script>
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

if __name__ == '__main__':
    app.run(debug=True) 