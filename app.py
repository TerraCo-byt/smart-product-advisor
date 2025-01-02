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
import json
import requests

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

# Configure session
app.config.update(
    SESSION_TYPE='filesystem',
    SESSION_FILE_DIR='/tmp/flask_session',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=1),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None'
)

# Initialize Flask-Session
Session(app)

# Allow CORS with credentials
CORS(app, 
     supports_credentials=True,
     resources={
         r"/*": {
             "origins": [
                 "https://admin.shopify.com",
                 "https://*.myshopify.com",
                 "https://*.onrender.com",
                 "http://localhost:8000",
                 "https://smart-advisor-test.myshopify.com"
             ],
             "methods": ["GET", "POST", "OPTIONS"],
             "allow_headers": [
                 "Content-Type",
                 "Authorization",
                 "X-Shop-Domain",
                 "X-Shopify-Access-Token",
                 "Origin",
                 "Accept"
             ],
             "expose_headers": [
                 "Content-Range",
                 "X-Content-Range"
             ],
             "supports_credentials": True,
             "max_age": 3600,
             "vary": "Origin"
         }
     })

# Basic configuration
SHOPIFY_API_KEY = os.environ.get('SHOPIFY_API_KEY')
SHOPIFY_API_SECRET = os.environ.get('SHOPIFY_API_SECRET')
APP_URL = os.environ.get('RENDER_EXTERNAL_URL', os.environ.get('APP_URL', 'http://localhost:8000'))
API_VERSION = '2023-04'

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
    """Main app interface"""
    try:
        shop = request.args.get('shop')
        host = request.args.get('host', '')
        
        logger.info(f"App page requested for shop: {shop}")
        logger.info(f"Host: {host}")
        logger.info(f"Session data: {dict(session)}")
        logger.info(f"Cookies: {request.cookies}")
        
        if not shop:
            logger.error("Missing shop parameter")
            return jsonify({"error": "Missing shop parameter"}), 400
            
        # Check session
        access_token = session.get('access_token')
        session_shop = session.get('shop')
        
        if not access_token or not session_shop or session_shop != shop:
            logger.error(f"Invalid session. Session shop: {session_shop}, Request shop: {shop}")
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
                    <script>
                        window.shopOrigin = "{{ shop }}";
                        window.host = "{{ host }}";
                    </script>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                            line-height: 1.6;
                            margin: 0;
                            padding: 20px;
                            background: #f5f5f5;
                        }
                        .container {
                            max-width: 800px;
                            margin: 0 auto;
                            background: white;
                            padding: 20px;
                            border-radius: 8px;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }
                        h1 {
                            color: #2c2c2c;
                            margin-bottom: 20px;
                        }
                        .form-group {
                            margin-bottom: 15px;
                        }
                        label {
                            display: block;
                            margin-bottom: 5px;
                            color: #4a4a4a;
                        }
                        select, input {
                            width: 100%;
                            padding: 8px;
                            border: 1px solid #ddd;
                            border-radius: 4px;
                            font-size: 14px;
                        }
                        button {
                            background: #008060;
                            color: white;
                            border: none;
                            padding: 10px 20px;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 16px;
                            width: 100%;
                        }
                        button:hover {
                            background: #006e52;
                        }
                        #recommendations {
                            margin-top: 20px;
                        }
                        .loading {
                            text-align: center;
                            padding: 20px;
                            display: none;
                        }
                        .error {
                            color: #d82c0d;
                            background: #fbeae5;
                            padding: 12px;
                            border-radius: 4px;
                            margin: 10px 0;
                            display: none;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Smart Product Advisor</h1>
                        <div id="error" class="error"></div>
                        <form id="recommendationForm">
                            <div class="form-group">
                                <label for="price_range">Price Range</label>
                                <select id="price_range" name="price_range" required>
                                    <option value="any">Any</option>
                                    <option value="0-50">Under $50</option>
                                    <option value="50-100">$50 - $100</option>
                                    <option value="100-200">$100 - $200</option>
                                    <option value="200+">$200+</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="category">Category</label>
                                <select id="category" name="category" required>
                                    <option value="any">Any</option>
                                    <option value="clothing">Clothing</option>
                                    <option value="accessories">Accessories</option>
                                    <option value="electronics">Electronics</option>
                                    <option value="home">Home & Garden</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="keywords">Keywords (comma-separated)</label>
                                <input type="text" id="keywords" name="keywords" placeholder="e.g., comfortable, durable, modern">
                            </div>
                            <button type="submit">Get Recommendations</button>
                        </form>
                        <div id="loading" class="loading">Loading recommendations...</div>
                        <div id="recommendations"></div>
                    </div>
                    <script>
                        document.getElementById('recommendationForm').addEventListener('submit', async (e) => {
                            e.preventDefault();
                            
                            const form = e.target;
                            const loading = document.getElementById('loading');
                            const recommendationsDiv = document.getElementById('recommendations');
                            const errorDiv = document.getElementById('error');
                            
                            // Reset UI
                            loading.style.display = 'block';
                            recommendationsDiv.innerHTML = '';
                            errorDiv.style.display = 'none';
                            
                            try {
                                const response = await fetch(`/api/recommendations?shop=${window.shopOrigin}`, {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json'
                                    },
                                    body: JSON.stringify({
                                        price_range: form.price_range.value,
                                        category: form.category.value,
                                        keywords: form.keywords.value.split(',').map(k => k.trim()).filter(k => k)
                                    }),
                                    credentials: 'include'
                                });
                                
                                const data = await response.json();
                                
                                if (!response.ok) {
                                    if (response.status === 401 && data.redirect_url) {
                                        window.location.href = data.redirect_url;
                                        return;
                                    }
                                    throw new Error(data.error || 'Failed to get recommendations');
                                }
                                
                                if (data.success && data.recommendations) {
                                    recommendationsDiv.innerHTML = `
                                        <h2>Recommended Products</h2>
                                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px;">
                                            ${data.recommendations.map(rec => `
                                                <div style="border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
                                                    ${rec.product.image_url ? 
                                                        `<img src="${rec.product.image_url}" alt="${rec.product.title}" style="width: 100%; height: 200px; object-fit: cover; border-radius: 4px;">` 
                                                        : ''
                                                    }
                                                    <h3 style="margin: 10px 0;">${rec.product.title}</h3>
                                                    <p style="color: #2c2c2c; font-weight: bold;">$${rec.product.price}</p>
                                                    <p style="font-size: 14px; color: #666;">${rec.explanation}</p>
                                                    <div style="background: #f0f0f0; border-radius: 10px; margin: 10px 0;">
                                                        <div style="background: #008060; width: ${rec.confidence_score * 100}%; height: 10px; border-radius: 10px;"></div>
                                                    </div>
                                                    <p style="text-align: center; font-size: 12px; color: #666;">${Math.round(rec.confidence_score * 100)}% match</p>
                                                    <a href="${rec.product.url}" target="_blank" style="display: block; text-align: center; background: #008060; color: white; padding: 8px; border-radius: 4px; text-decoration: none;">View Product</a>
                                                </div>
                                            `).join('')}
                                        </div>
                                    `;
                                } else {
                                    throw new Error('No recommendations found');
                                }
                            } catch (error) {
                                errorDiv.textContent = error.message;
                                errorDiv.style.display = 'block';
                                recommendationsDiv.innerHTML = `
                                    <div style="text-align: center; padding: 20px; color: #666;">
                                        <p>Sorry, we couldn't get recommendations at this time.</p>
                                        <p>Please try again with different preferences.</p>
                                    </div>
                                `;
                            } finally {
                                loading.style.display = 'none';
                            }
                        });
                    </script>
                </body>
            </html>
        """, shop=shop, host=host))
        
        # Set security headers
        response.headers.update({
            'Content-Security-Policy': "frame-ancestors https://*.myshopify.com https://admin.shopify.com;",
            'Content-Type': 'text/html; charset=utf-8'
        })
        
        return response
        
    except Exception as e:
        logger.error(f"App page error: {str(e)}")
        logger.error("Full error details:", exc_info=True)
        return jsonify({"error": str(e)}), 500

def get_product_recommendations(products, preferences):
    """Generate AI-powered product recommendations"""
    try:
        logger.info(f"Starting recommendation generation with preferences: {preferences}")
        
        # Check for Hugging Face API token
        huggingface_token = os.environ.get('HUGGINGFACE_API_TOKEN')
        if not huggingface_token:
            logger.error("Missing HUGGINGFACE_API_TOKEN environment variable")
            raise Exception("Hugging Face API token not configured")
            
        if not huggingface_token.startswith('hf_'):
            logger.error("Invalid Hugging Face API token format")
            raise Exception("Invalid Hugging Face API token format")
        
        # Validate products
        if not products or not isinstance(products, list):
            logger.error(f"Invalid products data type: {type(products)}")
            raise Exception("Invalid products data")
            
        # Prepare product context
        try:
            product_context = "\n".join([
                f"Product {i+1}:"
                f"\nTitle: {p.title}"
                f"\nType: {p.product_type}"
                f"\nPrice: ${p.variants[0].price if p.variants else 'N/A'}"
                f"\nDescription: {p.body_html if hasattr(p, 'body_html') else 'No description'}"
                f"\nTags: {', '.join(p.tags) if hasattr(p, 'tags') else 'No tags'}"
                for i, p in enumerate(products)
            ])
            logger.info("Successfully prepared product context")
        except Exception as e:
            logger.error(f"Error preparing product context: {str(e)}")
            raise Exception(f"Failed to prepare product data: {str(e)}")
        
        # Prepare user preferences
        try:
            user_prefs = (
                f"Price Range: {preferences.get('price_range', 'Any')}\n"
                f"Category: {preferences.get('category', 'Any')}\n"
                f"Keywords: {', '.join(preferences.get('keywords', []))}"
            )
            logger.info("Successfully prepared user preferences")
        except Exception as e:
            logger.error(f"Error preparing user preferences: {str(e)}")
            raise Exception(f"Failed to prepare preferences: {str(e)}")
        
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

        logger.info("Successfully constructed prompts")

        # Make request to Hugging Face
        headers = {
            "Authorization": f"Bearer {huggingface_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "inputs": f"{system_prompt}\n\n{user_prompt}",
            "parameters": {
                "max_new_tokens": 1000,
                "temperature": 0.7,
                "return_full_text": False
            }
        }
        
        logger.info("Making request to Hugging Face API...")
        
        try:
            response = requests.post(
                "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            logger.info(f"Hugging Face API response status: {response.status_code}")
            logger.info(f"Hugging Face API response headers: {dict(response.headers)}")
            
            if response.status_code == 401:
                logger.error("Unauthorized: Invalid Hugging Face API token")
                raise Exception("Invalid Hugging Face API token")
            elif response.status_code == 503:
                logger.error("Model is loading")
                raise Exception("The recommendation model is currently loading. Please try again in a few moments.")
            elif response.status_code != 200:
                logger.error(f"Hugging Face API error response: {response.text}")
                raise Exception(f"Hugging Face API error: {response.text}")
                
            # Parse recommendations
            try:
                response_data = response.json()
                logger.info(f"Raw API response: {response_data}")
                
                recommendations_text = response_data[0]["generated_text"]
                json_str = recommendations_text.strip()
                
                # Extract JSON from markdown code blocks if present
                if "```json" in json_str:
                    json_str = json_str.split("```json")[1].split("```")[0]
                elif "```" in json_str:
                    json_str = json_str.split("```")[1]
                    
                logger.info(f"Extracted JSON string: {json_str}")
                
                recommendations = json.loads(json_str)
                logger.info(f"Parsed recommendations: {recommendations}")
                
                if not isinstance(recommendations, list):
                    raise Exception("Invalid recommendations format")
                    
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse recommendations JSON: {str(e)}")
                logger.error(f"Raw text: {recommendations_text}")
                raise Exception("Failed to parse recommendations data")
            except Exception as e:
                logger.error(f"Error processing recommendations: {str(e)}")
                raise Exception(f"Failed to process recommendations: {str(e)}")
            
            # Format recommendations
            formatted_recommendations = []
            for rec in recommendations:
                try:
                    product_idx = rec['product_index'] - 1
                    if 0 <= product_idx < len(products):
                        product = products[product_idx]
                        formatted_rec = {
                            'product': {
                                'title': product.title,
                                'price': float(product.variants[0].price if product.variants else 0),
                                'image_url': product.images[0].src if product.images else None,
                                'url': f"https://{request.headers.get('X-Shop-Domain')}/products/{product.handle}"
                            },
                            'confidence_score': float(rec['confidence_score']),
                            'explanation': rec['explanation']
                        }
                        formatted_recommendations.append(formatted_rec)
                except Exception as e:
                    logger.error(f"Error formatting recommendation {rec}: {str(e)}")
                    continue
                    
            if not formatted_recommendations:
                raise Exception("No valid recommendations could be generated")
                
            logger.info(f"Successfully formatted {len(formatted_recommendations)} recommendations")
            return formatted_recommendations
            
        except requests.exceptions.Timeout:
            logger.error("Request to Hugging Face API timed out")
            raise Exception("Recommendation service timed out")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request to Hugging Face API failed: {str(e)}")
            raise Exception(f"Failed to connect to recommendation service: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error generating recommendations: {str(e)}")
        logger.error("Full error details:", exc_info=True)
        raise

@app.route('/api/recommendations', methods=['POST'])
def recommendations():
    """Handle recommendation requests"""
    try:
        # Get shop parameter
        shop = request.args.get('shop')
        if not shop:
            shop = request.headers.get('X-Shop-Domain')
        if not shop:
            logger.error("Missing shop parameter")
            return jsonify({"error": "Missing shop parameter"}), 400
            
        logger.info(f"Processing request for shop: {shop}")
        logger.info(f"Headers: {dict(request.headers)}")
        
        # Get request data
        try:
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()
                
            logger.info(f"Request data: {data}")
            
            if not data:
                data = json.loads(request.get_data().decode('utf-8'))
                
        except Exception as e:
            logger.error(f"Error parsing request data: {str(e)}")
            return jsonify({
                "error": "Invalid request data",
                "details": str(e)
            }), 400
            
        # Process preferences
        try:
            keywords = data.get('keywords', '')
            if isinstance(keywords, str):
                keywords = [k.strip() for k in keywords.split(',') if k.strip()]
            elif isinstance(keywords, list):
                keywords = [k.strip() for k in keywords if k.strip()]
            else:
                keywords = []
                
            preferences = {
                'price_range': data.get('price_range', 'any'),
                'category': data.get('category', 'any'),
                'keywords': keywords
            }
            
            logger.info(f"Processed preferences: {preferences}")
            
        except Exception as e:
            logger.error(f"Error processing preferences: {str(e)}")
            return jsonify({
                "error": "Failed to process preferences",
                "details": str(e)
            }), 400
            
        # Setup Shopify session
        try:
            shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
            shopify_session = shopify.Session(shop, API_VERSION)
            
            # Try to get access token from session or request
            access_token = None
            if session and 'access_token' in session:
                access_token = session.get('access_token')
                logger.info("Got access token from session")
            
            if not access_token:
                logger.error("No access token found")
                return jsonify({
                    "error": "Authentication required",
                    "redirect_url": f"/install?shop={shop}"
                }), 401
                
            shopify_session.token = access_token
            shopify.ShopifyResource.activate_session(shopify_session)
            logger.info("Activated Shopify session")
            
        except Exception as e:
            logger.error(f"Failed to setup Shopify session: {str(e)}")
            return jsonify({
                "error": "Failed to setup Shopify session",
                "details": str(e)
            }), 500
            
        try:
            # Get products
            logger.info("Fetching products...")
            products = shopify.Product.find(limit=20)
            
            if not products:
                logger.error("No products found in shop")
                return jsonify({
                    "error": "No products found in shop"
                }), 404
                
            product_count = len(products)
            logger.info(f"Found {product_count} products")
            
            # Generate recommendations
            logger.info("Generating recommendations...")
            recommendations = get_product_recommendations(products, preferences)
            
            if not recommendations:
                logger.error("No recommendations generated")
                return jsonify({
                    "error": "No recommendations could be generated"
                }), 404
                
            logger.info(f"Generated {len(recommendations)} recommendations")
            
            # Sort and limit recommendations
            recommendations.sort(key=lambda x: x['confidence_score'], reverse=True)
            recommendations = recommendations[:6]
            
            # Prepare response
            response_data = {
                "success": True,
                "recommendations": recommendations
            }
            
            # Create response with CORS headers
            response = make_response(jsonify(response_data))
            response.headers.update({
                'Access-Control-Allow-Origin': request.headers.get('Origin', '*'),
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Credentials': 'true',
                'Vary': 'Origin'
            })
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            logger.error("Full error details:", exc_info=True)
            return jsonify({
                "error": "Failed to generate recommendations",
                "details": str(e)
            }), 500
            
        finally:
            try:
                shopify.ShopifyResource.clear_session()
                logger.info("Cleared Shopify session")
            except Exception as e:
                logger.error(f"Error clearing session: {str(e)}")
                
    except Exception as e:
        logger.error(f"Error in recommendations endpoint: {str(e)}")
        logger.error("Full error details:", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.after_request
def after_request(response):
    """Add CORS headers to all responses"""
    origin = request.headers.get('Origin')
    if origin:
        # Check if origin is allowed
        allowed_origins = [
            "https://admin.shopify.com",
            "https://*.myshopify.com",
            "https://*.onrender.com",
            "http://localhost:8000",
            "https://smart-advisor-test.myshopify.com"
        ]
        
        # Check if origin matches any allowed pattern
        is_allowed = any(
            origin == allowed or  # Exact match
            (allowed.startswith('https://*.') and origin.endswith(allowed[8:]))  # Wildcard match
            for allowed in allowed_origins
        )
        
        if is_allowed:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Shop-Domain, X-Shopify-Access-Token, Origin, Accept'
            response.headers['Access-Control-Max-Age'] = '3600'
            response.headers['Vary'] = 'Origin'
    
    return response

@app.route('/api/recommendations', methods=['OPTIONS'])
def recommendations_options():
    """Handle CORS preflight requests"""
    origin = request.headers.get('Origin')
    response = make_response()
    
    if origin:
        # Check if origin is allowed
        allowed_origins = [
            "https://admin.shopify.com",
            "https://*.myshopify.com",
            "https://*.onrender.com",
            "http://localhost:8000",
            "https://smart-advisor-test.myshopify.com"
        ]
        
        # Check if origin matches any allowed pattern
        is_allowed = any(
            origin == allowed or  # Exact match
            (allowed.startswith('https://*.') and origin.endswith(allowed[8:]))  # Wildcard match
            for allowed in allowed_origins
        )
        
        if is_allowed:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Shop-Domain, X-Shopify-Access-Token, Origin, Accept'
            response.headers['Access-Control-Max-Age'] = '3600'
            response.headers['Vary'] = 'Origin'
    
    return response

@app.route('/test-huggingface')
def test_huggingface():
    """Test endpoint to verify Hugging Face API connection"""
    try:
        logger.info("Starting Hugging Face API test")
        
        # Check for Hugging Face API token
        huggingface_token = os.environ.get('HUGGINGFACE_API_TOKEN')
        if not huggingface_token:
            logger.error("Missing HUGGINGFACE_API_TOKEN environment variable")
            return jsonify({
                "success": False,
                "error": "Missing HUGGINGFACE_API_TOKEN environment variable"
            }), 500
            
        if not huggingface_token.startswith('hf_'):
            logger.error("Invalid Hugging Face API token format")
            return jsonify({
                "success": False,
                "error": "Invalid Hugging Face API token format"
            }), 500
        
        logger.info("API token validation passed")
        
        # Make a simple test request to Hugging Face
        headers = {
            "Authorization": f"Bearer {huggingface_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "inputs": "Hello, this is a test request.",
            "parameters": {
                "max_new_tokens": 10,
                "temperature": 0.5,
                "return_full_text": False
            }
        }
        
        logger.info("Making test request to Hugging Face API...")
        logger.info(f"Using API token starting with: {huggingface_token[:5]}...")
        
        try:
            response = requests.post(
                "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            logger.info(f"Hugging Face API response status: {response.status_code}")
            logger.info(f"Hugging Face API response headers: {dict(response.headers)}")
            logger.info(f"Hugging Face API response: {response.text}")
            
            if response.status_code == 401:
                return jsonify({
                    "success": False,
                    "error": "Invalid Hugging Face API token",
                    "status_code": response.status_code,
                    "response": response.text
                }), 401
            elif response.status_code == 503:
                return jsonify({
                    "success": False,
                    "error": "Hugging Face API is currently loading the model",
                    "status_code": response.status_code,
                    "response": response.text
                }), 503
            elif response.status_code != 200:
                return jsonify({
                    "success": False,
                    "error": f"Hugging Face API error: {response.text}",
                    "status_code": response.status_code,
                    "response": response.text
                }), response.status_code
                
            response_data = response.json()
            logger.info("Successfully received response from Hugging Face API")
            
            return jsonify({
                "success": True,
                "message": "Successfully connected to Hugging Face API",
                "response": response_data
            })
            
        except requests.exceptions.Timeout:
            logger.error("Request to Hugging Face API timed out")
            return jsonify({
                "success": False,
                "error": "Request to Hugging Face API timed out"
            }), 504
        except requests.exceptions.RequestException as e:
            logger.error(f"Request to Hugging Face API failed: {str(e)}")
            return jsonify({
                "success": False,
                "error": f"Failed to connect to Hugging Face API: {str(e)}"
            }), 500
            
    except Exception as e:
        logger.error(f"Test endpoint error: {str(e)}")
        logger.error("Full error details:", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port) 