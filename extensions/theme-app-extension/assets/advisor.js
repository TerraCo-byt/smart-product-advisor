class SmartProductAdvisor {
  constructor(container) {
    this.container = container;
    this.apiUrl = container.dataset.apiUrl;
    this.shopDomain = container.dataset.shopDomain;
    this.accessToken = container.dataset.accessToken;
    this.origin = container.dataset.origin;
    
    // Elements
    this.button = container.querySelector('.smart-advisor-button');
    this.modal = container.querySelector('.smart-advisor-modal');
    this.closeButton = container.querySelector('.close-modal');
    this.form = container.querySelector('#advisor-form');
    this.recommendationsContainer = container.querySelector('#recommendations-container');
    
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
  }

  openModal() {
    this.modal.classList.add('active');
    document.body.classList.add('modal-open');
  }

  closeModal() {
    this.modal.classList.remove('active');
    document.body.classList.remove('modal-open');
  }

  async handleSubmit(e) {
    e.preventDefault();
    
    const form = e.target;
    const submitButton = form.querySelector('.submit-button');
    const originalButtonText = submitButton.textContent;
    
    try {
      // Show loading state
      submitButton.disabled = true;
      submitButton.textContent = 'Finding matches...';
      
      // Get form data
      const formData = new FormData(form);
      const data = {
        price_range: formData.get('price_range'),
        category: formData.get('category'),
        keywords: formData.get('keywords').split(',').map(k => k.trim()).filter(Boolean)
      };
      
      // Make API request
      const response = await fetch(`${this.apiUrl}/api/recommendations?shop=${this.shopDomain}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shop-Domain': this.shopDomain,
          'X-Shopify-Access-Token': this.accessToken,
          'Origin': window.location.origin,
          'Accept': 'application/json'
        },
        mode: 'cors',
        credentials: 'include',
        body: JSON.stringify(data)
      });
      
      if (!response.ok) {
        throw new Error('Failed to get recommendations');
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Failed to get recommendations');
      }
      
      // Display recommendations
      this.displayRecommendations(result.recommendations);
      
    } catch (error) {
      console.error('Error getting recommendations:', error);
      this.recommendationsContainer.innerHTML = `
        <div class="error-message">
          <p>Sorry, we couldn't get recommendations at this time.</p>
          <p>Please try again later.</p>
        </div>
      `;
      
    } finally {
      // Reset button state
      submitButton.disabled = false;
      submitButton.textContent = originalButtonText;
    }
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

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  const containers = document.querySelectorAll('.smart-advisor-container');
  containers.forEach(container => new SmartProductAdvisor(container));
}); 