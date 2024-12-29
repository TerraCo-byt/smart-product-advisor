import requests
import json
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_recommendations():
    # API endpoint
    url = "https://smart-product-advisor.onrender.com/api/mistral/recommend"
    
    # Test data
    test_data = {
        "preferences": {
            "price_range": "50-100",
            "category": "Poufs",
            "keywords": ["handmade", "velvet", "moroccan"]
        }
    }
    
    # Headers
    headers = {
        "Content-Type": "application/json",
        "X-Shop-Domain": "smart-advisor-test.myshopify.com",
        "Origin": "https://smart-advisor-test.myshopify.com"
    }
    
    try:
        # Log request details
        logger.debug(f"Sending request to: {url}")
        logger.debug(f"Headers: {json.dumps(headers, indent=2)}")
        logger.debug(f"Data: {json.dumps(test_data, indent=2)}")
        
        # Make the request
        print("\nSending request to recommendation API...")
        response = requests.post(url, json=test_data, headers=headers)
        
        # Check response status
        print(f"Response status code: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                recommendations = result['recommendations']
                print("\nRecommendations received:")
                for i, rec in enumerate(recommendations, 1):
                    print(f"\nRecommendation {i}:")
                    print(f"Product: {rec['product']['title']}")
                    print(f"Price: £{rec['product']['price']}")
                    print(f"Confidence: {rec['confidence_score']*100:.1f}%")
                    print(f"Explanation: {rec['explanation']}")
                    print(f"URL: {rec['product']['url']}")
            else:
                print("\nAPI request successful but no recommendations returned")
                print(f"Response content: {response.text}")
        else:
            print(f"\nError response status: {response.status_code}")
            print(f"Error response headers: {dict(response.headers)}")
            print(f"Error response content: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"\nNetwork error: {str(e)}")
        if hasattr(e, 'response'):
            print(f"Error response content: {e.response.text}")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    test_recommendations() 