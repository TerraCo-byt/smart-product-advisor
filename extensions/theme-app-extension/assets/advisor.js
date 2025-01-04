class SmartProductAdvisor {
  constructor(container) {
    this.container = container;
    this.apiUrl = container.dataset.apiUrl;
    this.shopDomain = container.dataset.shopDomain;
    this.accessToken = container.dataset.accessToken;
    this.origin = window.location.origin;
    
    // Elements
    this.button = container.querySelector('.smart-advisor-button');
    this.modal = container.querySelector('.smart-advisor-modal');
    this.closeButton = container.querySelector('.close-modal');
    this.form = container.querySelector('#advisor-form');
    this.recommendationsContainer = container.querySelector('#recommendations-container');
    this.loadingIndicator = container.querySelector('.loading-indicator');
    this.errorMessage = container.querySelector('.error-message');
    
    this.retryCount = 0;
    this.maxRetries = 3;
    this.retryDelay = 1000;
    
    this.init();
  }

  init() {
    // Show modal
    this.button.addEventListener('click', () => this.openModal());
    
    // Close modal
    this.closeButton.addEventListener('click', () => this.closeModal());
    
    // Handle form submission
    this.form.addEventListener('submit', (e) => this.handleSubmit(e));
    
    // Close on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.modal.classList.contains('active')) {
        this.closeModal();
      }
    });
    
    // Close on outside click
    document.addEventListener('click', (e) => {
      if (this.modal.classList.contains('active') && 
          !this.modal.contains(e.target) && 
          !this.button.contains(e.target)) {
        this.closeModal();
      }
    });

    // Add retry button handler
    if (this.errorMessage) {
      const retryButton = this.errorMessage.querySelector('.retry-button');
      if (retryButton) {
        retryButton.addEventListener('click', () => {
          this.errorMessage.style.display = 'none';
          this.handleSubmit(new Event('submit'));
        });
      }
    }
  }

  openModal() {
    this.modal.classList.add('active');
    document.body.classList.add('modal-open');
    this.resetState();
  }

  closeModal() {
    this.modal.classList.remove('active');
    document.body.classList.remove('modal-open');
  }

  resetState() {
    this.form.reset();
    this.recommendationsContainer.innerHTML = '';
    if (this.loadingIndicator) {
      this.loadingIndicator.style.display = 'none';
    }
    if (this.errorMessage) {
      this.errorMessage.style.display = 'none';
    }
    this.retryCount = 0;
  }

  async handleSubmit(e) {
    e.preventDefault();
    
    const form = e.target;
    const submitButton = form.querySelector('.submit-button');
    const buttonText = submitButton.querySelector('.button-text');
    const originalButtonText = buttonText ? buttonText.textContent : submitButton.textContent;
    
    try {
      // Show loading state
      submitButton.disabled = true;
      if (buttonText) {
        buttonText.textContent = 'Finding matches...';
      } else {
        submitButton.textContent = 'Finding matches...';
      }
      if (this.loadingIndicator) {
        this.loadingIndicator.style.display = 'flex';
      }
      if (this.errorMessage) {
        this.errorMessage.style.display = 'none';
      }
      
      // Get form data
      const formData = new FormData(form);
      const data = {
        price_range: formData.get('price_range'),
        category: formData.get('category'),
        keywords: formData.get('keywords').split(',').map(k => k.trim()).filter(Boolean)
      };
      
      // Make API request with retry logic
      const response = await this.makeRequestWithRetry(data);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to get recommendations');
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Failed to get recommendations');
      }
      
      // Display recommendations
      this.displayRecommendations(result.recommendations);
      
    } catch (error) {
      console.error('Error getting recommendations:', error);
      this.showError(error);
      
    } finally {
      // Reset button state
      submitButton.disabled = false;
      if (buttonText) {
        buttonText.textContent = originalButtonText;
      } else {
        submitButton.textContent = originalButtonText;
      }
      if (this.loadingIndicator) {
        this.loadingIndicator.style.display = 'none';
      }
    }
  }

  async makeRequestWithRetry(data, attempt = 1) {
    try {
      const headers = {
        'Content-Type': 'application/json',
        'X-Shop-Domain': this.shopDomain,
        'Origin': this.origin,
        'Accept': 'application/json'
      };

      // Only add access token if it exists
      if (this.accessToken) {
        headers['X-Shopify-Access-Token'] = this.accessToken;
      }

      const response = await fetch(`${this.apiUrl}/api/recommendations?shop=${this.shopDomain}`, {
        method: 'POST',
        headers: headers,
        mode: 'cors',
        credentials: 'include',
        body: JSON.stringify(data)
      });

      // Handle specific error cases
      if (response.status === 401) {
        const data = await response.json();
        if (data.redirect_url) {
          window.location.href = data.redirect_url;
          return null;
        }
      }

      // If response is 503 (service unavailable) or 429 (rate limit), retry
      if ((response.status === 503 || response.status === 429) && attempt < this.maxRetries) {
        const delay = this.retryDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.makeRequestWithRetry(data, attempt + 1);
      }

      return response;
    } catch (error) {
      console.error('Request error:', error);
      if (attempt < this.maxRetries) {
        const delay = this.retryDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.makeRequestWithRetry(data, attempt + 1);
      }
      throw error;
    }
  }

  showError(error) {
    const errorContainer = this.errorMessage || this.recommendationsContainer;
    const message = this.getErrorMessage(error);
    
    errorContainer.innerHTML = `
      <div class="error-message">
        <p>${message}</p>
        ${this.retryCount < this.maxRetries ? '<button class="retry-button">Try Again</button>' : ''}
        <small class="error-details">${error.message}</small>
      </div>
    `;
    
    if (this.errorMessage) {
      this.errorMessage.style.display = 'block';
    }

    // Add retry button handler
    const retryButton = errorContainer.querySelector('.retry-button');
    if (retryButton) {
      retryButton.addEventListener('click', () => {
        this.retryCount++;
        this.errorMessage.style.display = 'none';
        this.handleSubmit(new Event('submit'));
      });
    }
  }

  getErrorMessage(error) {
    if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
      return 'Unable to connect to the recommendation service. Please check your internet connection.';
    }
    if (error.message.includes('401') || error.message.includes('Authentication')) {
      return 'Session expired. Please refresh the page and try again.';
    }
    if (error.message.includes('429')) {
      return 'Too many requests. Please wait a moment and try again.';
    }
    if (error.message.includes('503')) {
      return 'Service temporarily unavailable. Please try again in a few moments.';
    }
    if (error.message.includes('CORS')) {
      return 'Unable to connect to the recommendation service due to security restrictions. Please try refreshing the page.';
    }
    return 'Sorry, we couldn\'t get recommendations at this time. Please try again later.';
  }

  displayRecommendations(recommendations) {
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
          <div class="product-image-container">
            ${rec.product.image_url ? 
              `<img src="${rec.product.image_url}" alt="${rec.product.title}" loading="lazy">` : 
              '<div class="no-image">No image available</div>'
            }
          </div>
          <h3>${rec.product.title}</h3>
          <div class="price">£${rec.product.price.toFixed(2)}</div>
          <div class="match-score">
            <div class="score-bar" style="--score: ${confidence}%"></div>
            <span>${confidence}% match</span>
          </div>
          <p class="explanation">${rec.explanation}</p>
          <a href="${rec.product.url}" class="view-product" target="_blank" rel="noopener">View Product</a>
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