const express = require('express');
const cors = require('cors');
const axios = require('axios');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(morgan('combined'));

// CORS configuration with preflight handling
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);

    // Allow all Shopify-related domains and localhost
    if (
      origin.endsWith('.myshopify.com') ||
      origin === 'https://admin.shopify.com' ||
      origin.includes('.shopify.com') ||
      origin.startsWith('http://localhost:') ||
      origin.startsWith('https://localhost:') ||
      // Allow password page domains
      origin.includes('shopifypreview.com')
    ) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Shop-Domain',
    'X-Shopify-Access-Token',
    'X-CSRF-Token',
    'Origin',
    'Accept',
    'X-Requested-With',
    'X-Shopify-Preview', // Add preview header
    'Cookie' // Allow cookie header for password sessions
  ],
  exposedHeaders: [
    'Content-Range', 
    'X-Content-Range',
    'Set-Cookie' // Allow setting cookies
  ],
  credentials: true,
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Handle preflight requests
app.options('*', cors());

// Retry configuration
const axiosRetry = require('axios-retry');
axiosRetry(axios, { 
  retries: 3,
  retryDelay: axiosRetry.exponentialDelay,
  retryCondition: (error) => {
    return axiosRetry.isNetworkOrIdempotentRequestError(error) || 
           (error.response && error.response.status === 503);
  }
});

// GraphQL query for products
const PRODUCTS_QUERY = `
  query GetProducts($first: Int!) {
    products(first: $first) {
      edges {
        node {
          id
          title
          description
          priceRangeV2 {
            minVariantPrice {
              amount
              currencyCode
            }
          }
          images(first: 1) {
            edges {
              node {
                url
                altText
              }
            }
          }
          variants(first: 1) {
            edges {
              node {
                id
                price
                title
              }
            }
          }
          tags
          productType
          onlineStoreUrl
        }
      }
    }
  }
`;

// Shopify app proxy endpoint
app.post('/apps/smart-advisor/proxy/recommendations', async (req, res) => {
  try {
    console.log('Received Shopify proxy request:', {
      body: req.body,
      headers: req.headers,
      origin: req.headers.origin
    });

    // Set CORS headers early
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');

    // Get shop domain from various possible sources
    let shopDomain = req.headers['x-shop-domain'] || req.query.shop;
    
    // If no shop domain in headers, try to extract from origin or referer
    if (!shopDomain) {
      const origin = req.headers.origin || req.headers.referer;
      if (origin) {
        // Handle both myshopify.com and shopifypreview.com domains
        if (origin.includes('.myshopify.com')) {
          shopDomain = origin.split('//')[1].split('.myshopify.com')[0] + '.myshopify.com';
        } else if (origin.includes('shopifypreview.com')) {
          // Extract shop domain from preview URL
          const previewUrl = new URL(origin);
          shopDomain = previewUrl.searchParams.get('shop') || 
                      previewUrl.pathname.split('/')[1] + '.myshopify.com';
        }
      }
    }

    if (!shopDomain || !shopDomain.endsWith('.myshopify.com')) {
      return res.status(400).json({
        success: false,
        error: 'Invalid shop domain',
        details: 'A valid Shopify shop domain is required'
      });
    }

    // Get access token
    const accessToken = req.headers['x-shopify-access-token'];
    if (!accessToken) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized',
        details: 'Missing access token'
      });
    }

    // First, fetch products using GraphQL
    const graphqlResponse = await axios({
      method: 'POST',
      url: `https://${shopDomain}/admin/api/2024-01/graphql.json`,
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': accessToken,
        'X-Shopify-Preview': 'true', // Add preview header
        Cookie: req.headers.cookie // Forward cookies for password session
      },
      data: {
        query: PRODUCTS_QUERY,
        variables: {
          first: 20
        }
      }
    });

    // Transform GraphQL response
    const products = graphqlResponse.data.data.products.edges.map(edge => ({
      id: edge.node.id,
      title: edge.node.title,
      description: edge.node.description,
      price: parseFloat(edge.node.variants.edges[0]?.node.price || '0'),
      image_url: edge.node.images.edges[0]?.node.url,
      url: edge.node.onlineStoreUrl,
      tags: edge.node.tags,
      product_type: edge.node.productType
    }));

    // Get recommendations with retry logic
    const recommendationsResponse = await axios({
      method: 'POST',
      url: 'https://smart-product-advisor.onrender.com/api/recommendations',
      data: {
        ...req.body,
        products,
        shop: shopDomain,
        preview: true // Indicate this is a preview/password-protected request
      },
      headers: {
        'Content-Type': 'application/json',
        'X-Shop-Domain': shopDomain,
        'Origin': req.headers.origin || `https://${shopDomain}`,
        'X-Shopify-Preview': 'true',
        Cookie: req.headers.cookie
      },
      timeout: 15000,
      validateStatus: function (status) {
        return status >= 200 && status < 500;
      }
    });

    // Forward any cookies from the response
    if (recommendationsResponse.headers['set-cookie']) {
      res.header('Set-Cookie', recommendationsResponse.headers['set-cookie']);
    }

    if (recommendationsResponse.status === 503) {
      return res.status(503).json({
        success: false,
        error: 'Service Temporarily Unavailable',
        details: 'The recommendations service is currently unavailable. Please try again in a few moments.',
        retry_after: 5
      });
    }

    if (!recommendationsResponse.data.success) {
      return res.status(400).json({
        success: false,
        error: 'Failed to get recommendations',
        details: recommendationsResponse.data.error || 'Unknown error occurred'
      });
    }

    console.log('Proxy response successful');
    res.json({
      success: true,
      recommendations: recommendationsResponse.data.recommendations
    });
  } catch (error) {
    console.error('Proxy error:', error);

    let statusCode = 500;
    let errorMessage = 'Internal Server Error';
    let errorDetails = error.message;

    if (error.response) {
      statusCode = error.response.status;
      errorMessage = error.response.data?.error || 'API Error';
      errorDetails = error.response.data?.details || error.response.statusText;
      
      // Special handling for password protection
      if (statusCode === 401 && error.response.headers['www-authenticate']?.includes('StorefrontPassword')) {
        statusCode = 403;
        errorMessage = 'Store Password Required';
        errorDetails = 'This store is password protected. Please enter the store password to continue.';
      }
    } else if (error.request) {
      statusCode = 504;
      errorMessage = 'Gateway Timeout';
      errorDetails = 'No response received from API';
    }

    res.status(statusCode).json({
      success: false,
      error: errorMessage,
      details: errorDetails,
      status: statusCode,
      retry_after: statusCode === 503 ? 5 : undefined,
      requires_password: statusCode === 403
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    cors: 'enabled',
    api_version: '2024-01',
    preview_support: true
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
}); 