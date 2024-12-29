class SmartProductAdvisor {
  constructor(container) {
    this.container = container;
    this.apiUrl = container.dataset.apiUrl || 'https://smart-product-advisor.onrender.com';
    this.shopDomain = container.dataset.shopDomain;
    
    // Elements
    this.button = container.querySelector('.smart-advisor-button');
    this.modal = container.querySelector('.smart-advisor-modal');
    this.overlay = container.querySelector('.modal-overlay');
    this.closeButton = container.querySelector('.close-modal');
    this.form = container.querySelector('#advisor-form');
    this.recommendationsContainer = container.querySelector('#recommendations-container');
    this.loadingIndicator = this.recommendationsContainer.querySelector('.loading-indicator');
    this.errorMessage = this.recommendationsContainer.querySelector('.error-message');
    this.retryButton = this.errorMessage.querySelector('.retry-button');
    
    this.isVisible = false;
    this.setupEventListeners();
    this.setupScrollTrigger();
  }

  setupEventListeners() {
    // Show modal
    this.button.addEventListener('click', () => this.openModal());
    
    // Close modal
    this.closeButton.addEventListener('click', () => this.closeModal());
    this.overlay.addEventListener('click', () => this.closeModal());
    
    // Handle form submission
    this.form.addEventListener('submit', (e) => this.handleSubmit(e));
    
    // Retry button
    this.retryButton.addEventListener('click', () => {
      this.errorMessage.style.display = 'none';
      this.handleSubmit(new Event('submit'));
    });
    
    // Close on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.modal.classList.contains('active')) {
        this.closeModal();
      }
    });
  }

  setupScrollTrigger() {
    let lastScrollPosition = 0;
    let scrollTimeout;

    window.addEventListener('scroll', () => {
      clearTimeout(scrollTimeout);
      
      scrollTimeout = setTimeout(() => {
        const currentScroll = window.scrollY;
        const scrollPercent = (currentScroll / (document.documentElement.scrollHeight - window.innerHeight)) * 100;
        
        if (scrollPercent >= 30 && currentScroll > lastScrollPosition && !this.isVisible) {
          this.container.classList.add('visible');
          this.isVisible = true;
        }
        
        lastScrollPosition = currentScroll;
      }, 100);
    });
  }

  openModal() {
    this.modal.classList.add('active');
    this.overlay.classList.add('active');
    document.body.classList.add('modal-open');
    
    // Reset form and containers
    this.form.reset();
    this.recommendationsContainer.innerHTML = '';
    this.loadingIndicator.style.display = 'none';
    this.errorMessage.style.display = 'none';
  }

  closeModal() {
    this.modal.classList.remove('active');
    this.overlay.classList.remove('active');
    document.body.classList.remove('modal-open');
  }

  async handleSubmit(e) {
    e.preventDefault();
    
    const form = e.target;
    const submitButton = form.querySelector('.submit-button');
    const buttonText = submitButton.querySelector('.button-text');
    
    try {
      // Show loading state
      submitButton.disabled = true;
      buttonText.textContent = 'Finding matches...';
      this.loadingIndicator.style.display = 'flex';
      this.errorMessage.style.display = 'none';
      
      // Get form data
      const formData = new FormData(form);
      const keywords = formData.get('keywords').split(',').map(k => k.trim()).filter(Boolean);
      
      const data = {
        preferences: {
          price_range: formData.get('price_range'),
          category: formData.get('category'),
          keywords: keywords
        }
      };
      
      // Make API request
      const response = await fetch(`${this.apiUrl}/api/mistral/recommend`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shop-Domain': this.shopDomain
        },
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
      this.loadingIndicator.style.display = 'none';
      this.errorMessage.style.display = 'block';
      
    } finally {
      // Reset button state
      submitButton.disabled = false;
      buttonText.textContent = 'Find Perfect Matches';
      this.loadingIndicator.style.display = 'none';
    }
  }

  displayRecommendations(recommendations) {
    this.recommendationsContainer.innerHTML = '';
    
    if (!recommendations || recommendations.length === 0) {
      const noResults = document.createElement('div');
      noResults.className = 'no-results';
      noResults.innerHTML = `
        <p>No matching products found.</p>
        <p>Try adjusting your preferences and search again.</p>
      `;
      this.recommendationsContainer.appendChild(noResults);
      return;
    }
    
    recommendations.forEach(rec => {
      const card = document.createElement('div');
      card.className = 'product-card';
      
      const confidence = Math.round(rec.confidence_score * 100);
      
      card.innerHTML = `
        <div class="product-image-container">
          ${rec.product.image_url ? `<img src="${rec.product.image_url}" alt="${rec.product.title}">` : ''}
        </div>
        <h3>${rec.product.title}</h3>
        <div class="price">£${rec.product.price.toFixed(2)}</div>
        <div class="match-score">
          <div class="score-bar" style="--score: ${confidence}%"></div>
          <span>${confidence}% match</span>
        </div>
        <div class="explanation">${rec.explanation}</div>
        <a href="${rec.product.url}" class="view-product" target="_blank">View Product</a>
      `;
      
      this.recommendationsContainer.appendChild(card);
    });
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  const containers = document.querySelectorAll('.smart-advisor-container');
  containers.forEach(container => new SmartProductAdvisor(container));
}); 