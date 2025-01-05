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

    if (
      origin.endsWith('.myshopify.com') ||
      origin === 'https://admin.shopify.com' ||
      origin.includes('.shopify.com') ||
      origin.startsWith('http://localhost:') ||
      origin.startsWith('https://localhost:')
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
    'X-Requested-With'
  ],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

app.options('*', cors());

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

    // Validate shop domain
    const shopDomain = req.headers['x-shop-domain'] || req.query.shop;
    if (!shopDomain || !shopDomain.endsWith('.myshopify.com')) {
      return res.status(400).json({
        error: 'Invalid shop domain',
        details: 'A valid Shopify shop domain is required'
      });
    }

    // Get access token
    const accessToken = req.headers['x-shopify-access-token'];
    if (!accessToken) {
      return res.status(401).json({
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
        'X-Shopify-Access-Token': accessToken
      },
      data: {
        query: PRODUCTS_QUERY,
        variables: {
          first: 20 // Fetch up to 20 products
        }
      }
    });

    // Transform GraphQL response to the format expected by the recommendations API
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

    // Then get recommendations
    const recommendationsResponse = await axios({
      method: 'POST',
      url: 'https://smart-product-advisor.onrender.com/api/recommendations',
      data: {
        ...req.body,
        products // Pass the transformed products to the recommendations API
      },
      headers: {
        'Content-Type': 'application/json',
        'X-Shop-Domain': shopDomain,
        'Origin': req.headers.origin || `https://${shopDomain}`
      },
      timeout: 10000
    });

    // Set CORS headers
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');

    console.log('Proxy response successful');
    res.json(recommendationsResponse.data);
  } catch (error) {
    console.error('Proxy error:', error);

    if (error.response) {
      res.status(error.response.status).json({
        error: 'API Error',
        details: error.response.data,
        status: error.response.status
      });
    } else if (error.request) {
      res.status(504).json({
        error: 'Gateway Timeout',
        details: 'No response received from API',
        status: 504
      });
    } else {
      res.status(500).json({
        error: 'Internal Server Error',
        details: error.message,
        status: 500
      });
    }
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    cors: 'enabled',
    api_version: '2024-01'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
}); 