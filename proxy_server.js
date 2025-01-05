const express = require('express');
const cors = require('cors');
const axios = require('axios');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(morgan('combined')); // For request logging

// CORS configuration with preflight handling
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    // Check if the origin is a Shopify domain
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
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Handle preflight requests
app.options('*', cors());

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

    const response = await axios({
      method: 'POST',
      url: 'https://smart-product-advisor.onrender.com/api/recommendations',
      data: req.body,
      headers: {
        'Content-Type': 'application/json',
        'X-Shop-Domain': shopDomain,
        'X-Shopify-Access-Token': req.headers['x-shopify-access-token'],
        'Origin': req.headers.origin || `https://${shopDomain}`
      },
      timeout: 10000 // 10 second timeout
    });

    // Set CORS headers for the response
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');

    console.log('Proxy response:', {
      status: response.status,
      headers: response.headers
    });

    res.json(response.data);
  } catch (error) {
    console.error('Proxy error:', error);

    // Handle different types of errors
    if (error.response) {
      // API responded with error
      res.status(error.response.status).json({
        error: 'API Error',
        details: error.response.data,
        status: error.response.status
      });
    } else if (error.request) {
      // No response received
      res.status(504).json({
        error: 'Gateway Timeout',
        details: 'No response received from API',
        status: 504
      });
    } else {
      // Request setup error
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
    cors: 'enabled'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
}); 