const express = require('express');
const cors = require('cors');
const axios = require('axios');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(morgan('combined')); // For request logging

// CORS configuration
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = [
      'https://smart-advisor-test.myshopify.com',
      'https://admin.shopify.com',
      'http://localhost:3000',
      'http://localhost:8000'
    ];
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Shop-Domain',
    'X-Shopify-Access-Token',
    'Origin',
    'Accept'
  ],
  credentials: true
}));

// Proxy endpoint for recommendations
app.post('/api/proxy/recommendations', async (req, res) => {
  try {
    console.log('Received proxy request:', {
      body: req.body,
      headers: req.headers
    });

    const response = await axios({
      method: 'POST',
      url: 'https://smart-product-advisor.onrender.com/api/recommendations',
      data: req.body,
      headers: {
        'Content-Type': 'application/json',
        'X-Shop-Domain': req.headers['x-shop-domain'],
        'X-Shopify-Access-Token': req.headers['x-shopify-access-token']
      },
      timeout: 10000 // 10 second timeout
    });

    console.log('Proxy response:', {
      status: response.status,
      data: response.data
    });

    res.json(response.data);
  } catch (error) {
    console.error('Proxy error:', error);

    // Handle different types of errors
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      res.status(error.response.status).json({
        error: 'API Error',
        details: error.response.data
      });
    } else if (error.request) {
      // The request was made but no response was received
      res.status(504).json({
        error: 'Gateway Timeout',
        details: 'No response received from API'
      });
    } else {
      // Something happened in setting up the request that triggered an Error
      res.status(500).json({
        error: 'Internal Server Error',
        details: error.message
      });
    }
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
}); 