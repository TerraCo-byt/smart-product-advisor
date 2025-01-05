class SmartProductAdvisor {
  constructor(container) {
    this.container = container;
    // Use Shopify's App Proxy URL format
    this.apiUrl = '/apps/smart-product-advisor/proxy/recommendations';
    this.shopDomain = window.Shopify?.shop || window.location.hostname;
    this.retryAttempts = 3;
    this.retryDelay = 1000;
    
    // Elements
    this.form = container.querySelector('#smart-advisor-form');
    this.recommendationsContainer = container.querySelector('.recommendations-container');
    this.loadingIndicator = container.querySelector('.loading-indicator');
    this.errorMessage = container.querySelector('.error-message');
    
    this.init();
  }

  init() {
    if (this.form) {
      this.form.addEventListener('submit', (e) => this.handleSubmit(e));
    }
  }

  async handleSubmit(e) {
    e.preventDefault();
    
    try {
      this.showLoading();
      
      const formData = new FormData(e.target);
      const data = {
        price_range: formData.get('price_range'),
        category: formData.get('category'),
        keywords: formData.get('keywords').split(',').map(k => k.trim()).filter(Boolean)
      };

      const recommendations = await this.getRecommendations(data);
      if (recommendations) {
        this.displayRecommendations(recommendations);
      }
    } catch (error) {
      console.error('Error:', error);
      this.showError(error);
    } finally {
      this.hideLoading();
    }
  }

  async getRecommendations(params, attempt = 1) {
    try {
      // Add shop parameter for app proxy
      const queryParams = new URLSearchParams({
        shop: this.shopDomain,
        timestamp: Date.now(),
        signature: '' // Shopify will handle this
      });

      const response = await fetch(`${this.apiUrl}?${queryParams.toString()}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'include',
        body: JSON.stringify(params)
      });

      if (!response.ok) {
        if ((response.status === 429 || response.status === 503) && attempt < this.retryAttempts) {
          const delay = this.retryDelay * Math.pow(2, attempt - 1);
          await new Promise(resolve => setTimeout(resolve, delay));
          return this.getRecommendations(params, attempt + 1);
        }

        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data.recommendations;
    } catch (error) {
      if (attempt < this.retryAttempts) {
        const delay = this.retryDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.getRecommendations(params, attempt + 1);
      }
      throw error;
    }
  }

  showLoading() {
    if (this.loadingIndicator) {
      this.loadingIndicator.style.display = 'block';
    }
    if (this.recommendationsContainer) {
      this.recommendationsContainer.innerHTML = `
        <div class="loading">
          <div class="loading-spinner"></div>
          <div class="loading-text">Finding perfect matches for you...</div>
        </div>
      `;
    }
  }

  hideLoading() {
    if (this.loadingIndicator) {
      this.loadingIndicator.style.display = 'none';
    }
  }

  showError(error) {
    const container = this.errorMessage || this.recommendationsContainer;
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

  displayRecommendations(recommendations) {
    if (!this.recommendationsContainer) return;

    if (!recommendations || recommendations.length === 0) {
      this.recommendationsContainer.innerHTML = `
        <div class="no-results">
          <p>No matching products found.</p>
          <p>Try adjusting your preferences and search again.</p>
        </div>
      `;
      return;
    }

    this.recommendationsContainer.innerHTML = recommendations.map(rec => {
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
}

// Initialize with error handling
document.addEventListener('DOMContentLoaded', () => {
  try {
    const containers = document.querySelectorAll('.smart-advisor-container');
    containers.forEach(container => {
      try {
        new SmartProductAdvisor(container);
      } catch (error) {
        console.error('Error initializing advisor for container:', error);
        container.innerHTML = `
          <div class="error-message">
            <p>Sorry, we couldn't initialize the product advisor.</p>
            <small class="error-details">${error.message}</small>
          </div>
        `;
      }
    });
  } catch (error) {
    console.error('Error initializing Smart Product Advisor:', error);
  }
}); 