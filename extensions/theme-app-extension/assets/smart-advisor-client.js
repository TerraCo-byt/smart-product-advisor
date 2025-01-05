class SmartAdvisorClient {
    constructor() {
        // Use Shopify's proxy path to avoid CORS
        this.baseUrl = '/apps/smart-advisor';
        this.proxyPath = '/proxy';
        this.retryAttempts = 3;
        this.retryDelay = 1000;
        
        // Get shop domain from meta tag or URL
        this.shopDomain = this.getShopDomain();
    }

    getShopDomain() {
        // Try to get from meta tag first
        const metaTag = document.querySelector('meta[name="shopify-shop-domain"]');
        if (metaTag) {
            return metaTag.content;
        }
        
        // Fallback to URL parsing
        const hostname = window.location.hostname;
        if (hostname.includes('myshopify.com')) {
            return hostname;
        }
        
        // Final fallback
        return null;
    }

    async getRecommendations(params, attempt = 1) {
        try {
            this.showLoading();

            // Validate shop domain
            if (!this.shopDomain) {
                throw new Error('Shop domain not found');
            }

            const response = await fetch(`${this.baseUrl}${this.proxyPath}/recommendations`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Shop-Domain': this.shopDomain,
                    'X-Requested-With': 'XMLHttpRequest',
                    ...(window.csrfToken && {
                        'X-CSRF-Token': window.csrfToken
                    })
                },
                credentials: 'include',
                mode: 'cors',
                body: JSON.stringify({
                    ...params,
                    shop: this.shopDomain
                })
            });

            if (!response.ok) {
                // Handle specific error cases
                if (response.status === 401) {
                    const data = await response.json();
                    if (data.redirect_url) {
                        window.location.href = data.redirect_url;
                        return null;
                    }
                }

                // Retry on specific status codes
                if ((response.status === 429 || response.status === 503) && attempt < this.retryAttempts) {
                    const delay = this.retryDelay * Math.pow(2, attempt - 1);
                    await new Promise(resolve => setTimeout(resolve, delay));
                    return this.getRecommendations(params, attempt + 1);
                }

                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || 'Failed to get recommendations');
            }

            this.hideLoading();
            return data.recommendations;
        } catch (error) {
            console.error('Smart Advisor Error:', error);
            
            // Retry on network errors
            if ((error.name === 'TypeError' || error.message.includes('Failed to fetch')) && attempt < this.retryAttempts) {
                const delay = this.retryDelay * Math.pow(2, attempt - 1);
                await new Promise(resolve => setTimeout(resolve, delay));
                return this.getRecommendations(params, attempt + 1);
            }

            this.hideLoading();
            this.handleError(error);
            return null;
        }
    }

    showLoading() {
        const container = document.querySelector('.recommendations-container');
        if (container) {
            container.innerHTML = `
                <div class="loading">
                    <div class="loading-spinner"></div>
                    <div class="loading-text">Finding perfect matches for you...</div>
                </div>
            `;
        }
    }

    hideLoading() {
        const loading = document.querySelector('.loading');
        if (loading) {
            loading.remove();
        }
    }

    handleError(error) {
        console.error('Smart Advisor Error:', error);
        const container = document.querySelector('.recommendations-container');
        if (container) {
            container.innerHTML = `
                <div class="error-message">
                    <div class="error-icon">⚠️</div>
                    <div class="error-text">
                        ${this.getErrorMessage(error)}
                    </div>
                    <button onclick="window.location.reload()" class="retry-button">
                        Try Again
                    </button>
                </div>
            `;
        }
    }

    getErrorMessage(error) {
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            return 'Unable to connect to the recommendation service. Please check your internet connection.';
        }
        if (error.message.includes('429')) {
            return 'Too many requests. Please wait a moment and try again.';
        }
        if (error.message.includes('503')) {
            return 'Service temporarily unavailable. Please try again in a few moments.';
        }
        return 'Sorry, we couldn\'t get recommendations at this time. Please try again later.';
    }
}

// Initialize and set up event listeners
document.addEventListener('DOMContentLoaded', () => {
    const advisor = new SmartAdvisorClient();
    
    const form = document.querySelector('#smart-advisor-form');
    if (form) {
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            const formData = new FormData(form);
            const params = {
                price_range: formData.get('price_range'),
                category: formData.get('category'),
                keywords: formData.get('keywords').split(',').map(k => k.trim()).filter(Boolean)
            };
            
            const recommendations = await advisor.getRecommendations(params);
            if (recommendations) {
                displayRecommendations(recommendations);
            }
        });
    }
});

function displayRecommendations(recommendations) {
    const container = document.querySelector('.recommendations-container');
    if (!container) return;

    if (!recommendations || recommendations.length === 0) {
        container.innerHTML = `
            <div class="no-results">
                <p>No matching products found.</p>
                <p>Try adjusting your preferences and search again.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = recommendations.map(rec => {
        const confidence = Math.round(rec.confidence_score * 100);
        return `
            <div class="product-card">
                <div class="product-image">
                    ${rec.product.image_url ? 
                        `<img src="${rec.product.image_url}" alt="${rec.product.title}" loading="lazy">` :
                        '<div class="no-image">No image available</div>'
                    }
                </div>
                <div class="product-info">
                    <h3>${rec.product.title}</h3>
                    <div class="price">£${rec.product.price.toFixed(2)}</div>
                    <div class="match-score">
                        <div class="score-bar" style="--score: ${confidence}%"></div>
                        <span>${confidence}% match</span>
                    </div>
                    <p class="explanation">${rec.explanation}</p>
                    <a href="${rec.product.url}" class="view-product" target="_blank" rel="noopener">
                        View Product
                    </a>
                </div>
            </div>
        `;
    }).join('');
}

// Add required styles
const styles = `
    .loading {
        text-align: center;
        padding: 20px;
    }
    .loading-spinner {
        border: 4px solid #f3f3f3;
        border-top: 4px solid #000;
        border-radius: 50%;
        width: 40px;
        height: 40px;
        animation: spin 1s linear infinite;
        margin: 0 auto 10px;
    }
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    .loading-text {
        color: #666;
    }
    .error-message {
        color: #dc3545;
        padding: 20px;
        text-align: center;
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .error-icon {
        font-size: 24px;
        margin-bottom: 10px;
    }
    .error-text {
        margin-bottom: 15px;
    }
    .retry-button {
        margin-top: 10px;
        padding: 8px 16px;
        background: #000;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        transition: background 0.2s;
    }
    .retry-button:hover {
        background: #333;
    }
    .product-card {
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 20px;
        display: flex;
        gap: 20px;
        background: #fff;
    }
    .product-image {
        width: 150px;
        height: 150px;
        overflow: hidden;
        border-radius: 4px;
    }
    .product-image img {
        width: 100%;
        height: 100%;
        object-fit: cover;
    }
    .no-image {
        width: 100%;
        height: 100%;
        background: #f5f5f5;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #666;
    }
    .product-info {
        flex: 1;
    }
    .match-score {
        margin: 10px 0;
    }
    .score-bar {
        height: 4px;
        background: #eee;
        border-radius: 2px;
        margin-bottom: 5px;
        position: relative;
    }
    .score-bar::before {
        content: '';
        position: absolute;
        left: 0;
        top: 0;
        height: 100%;
        width: var(--score);
        background: #4CAF50;
        border-radius: 2px;
    }
    .view-product {
        display: inline-block;
        padding: 8px 16px;
        background: #000;
        color: white;
        text-decoration: none;
        border-radius: 4px;
        margin-top: 10px;
        transition: background 0.2s;
    }
    .view-product:hover {
        background: #333;
    }
`;

// Add styles to document
const styleSheet = document.createElement('style');
styleSheet.textContent = styles;
document.head.appendChild(styleSheet); 