import requests
import json
import logging
import shopify
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SHOP_DOMAIN = "smart-advisor-test.myshopify.com"
APP_URL = "https://smart-product-advisor.onrender.com"
API_VERSION = "2023-07"

# Shopify API credentials
SHOPIFY_API_KEY = os.environ.get('SHOPIFY_API_KEY')
SHOPIFY_API_SECRET = os.environ.get('SHOPIFY_API_SECRET')

def test_recommendations():
    """Test the recommendation API endpoint"""
    url = f"{APP_URL}/api/recommendations"
    
    # Test data
    test_data = {
        "preferences": {
            "price_range": "0-500",  # Wider range to ensure we get results
            "category": "",  # Empty to get all categories
            "keywords": ["modern", "stylish"]  # Simple keywords
        }
    }
    
    # Headers
    headers = {
        "Content-Type": "application/json",
        "X-Shop-Domain": SHOP_DOMAIN,
        "Origin": f"https://{SHOP_DOMAIN}",
        "Accept": "application/json"
    }
    
    try:
        # Initialize Shopify API
        shopify.Session.setup(api_key=SHOPIFY_API_KEY, secret=SHOPIFY_API_SECRET)
        session = shopify.Session(SHOP_DOMAIN, API_VERSION)
        
        logger.info("Making request to recommendation API...")
        logger.info(f"Request URL: {url}")
        logger.info(f"Request data: {json.dumps(test_data, indent=2)}")
        
        # Make request with session
        response = requests.post(
            url, 
            json=test_data, 
            headers=headers,
            cookies={"session": "true"},
            allow_redirects=True
        )
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            result = response.json()
            logger.info("Recommendations received successfully:")
            logger.info(json.dumps(result, indent=2))
            return result
        else:
            logger.error(f"Error response: {response.text}")
            # Try to parse error response
            try:
                error_data = response.json()
                logger.error(f"Detailed error: {json.dumps(error_data, indent=2)}")
            except:
                logger.error("Could not parse error response as JSON")
            return None
            
    except Exception as e:
        logger.error(f"Error making request: {str(e)}")
        logger.error("Full error:", exc_info=True)
        return None

if __name__ == "__main__":
    if not SHOPIFY_API_KEY or not SHOPIFY_API_SECRET:
        logger.error("Missing Shopify API credentials. Please set SHOPIFY_API_KEY and SHOPIFY_API_SECRET environment variables.")
        exit(1)
    test_recommendations() 