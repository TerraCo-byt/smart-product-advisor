# Smart Product Advisor Proxy Server

This proxy server handles CORS and authentication for the Smart Product Advisor Shopify app.

## Features

- CORS handling for Shopify store domains
- Request proxying to main API
- Error handling and retry logic
- Request logging
- Health check endpoint

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create `.env` file with required environment variables:
```env
PORT=3000
NODE_ENV=production
ALLOWED_ORIGINS=https://your-store.myshopify.com,https://admin.shopify.com
API_URL=https://your-api-url.com
```

3. Start the server:
```bash
# Development
npm run dev

# Production
npm start
```

## API Endpoints

### POST /api/proxy/recommendations
Proxies recommendation requests to the main API.

### GET /health
Health check endpoint.

## Error Handling

The proxy server handles various error scenarios:
- Network errors
- API timeouts
- Rate limiting
- Server errors

## Deployment

1. Deploy to your preferred hosting service (e.g., Render, Heroku)
2. Set environment variables in your hosting platform
3. Update the API URL in your Shopify theme code

## Security

- CORS is configured to only allow requests from specified Shopify domains
- Headers are properly validated and forwarded
- Sensitive information is handled securely

## Monitoring

- Request logging via Morgan
- Error tracking and reporting
- Health check endpoint for uptime monitoring 