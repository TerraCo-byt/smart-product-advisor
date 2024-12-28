class SmartAdvisor {
  constructor() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.initialize());
    } else {
      this.initialize();
    }
  }

  initialize() {
    this.container = document.querySelector('.smart-advisor-container');
    if (!this.container) return;
    
    this.button = this.container.querySelector('.smart-advisor-button');
    this.modal = this.container.querySelector('.smart-advisor-modal');
    this.closeButton = this.container.querySelector('.close-modal');
    this.form = this.container.querySelector('#advisor-form');
    
    this.apiUrl = this.container.dataset.apiUrl || 'https://smart-product-advisor.onrender.com';
    this.shopDomain = this.container.dataset.shopDomain;
    this.productId = this.container.dataset.productId;
    this.hasShown = false;
    this.isLoading = false;
    
    this.init();
  }

  init() {
    if (!this.button || !this.modal || !this.closeButton || !this.form) {
      console.error('Required elements not found');
      return;
    }
    
    this.initScrollBehavior();
    
    this.button.addEventListener('click', () => this.openModal());
    this.closeButton.addEventListener('click', (e) => {
      e.stopPropagation();
      this.closeModal();
    });
    this.form.addEventListener('submit', (e) => this.handleSubmit(e));
    
    document.addEventListener('click', (e) => {
      if (this.modal.classList.contains('active') && 
          !this.modal.contains(e.target) && 
          !this.button.contains(e.target)) {
        this.closeModal();
      }
    });

    this.modal.addEventListener('click', (e) => {
      e.stopPropagation();
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.modal.classList.contains('active')) {
        this.closeModal();
      }
    });

    this.container.style.display = 'none';
  }

  initScrollBehavior() {
    let lastScrollPosition = 0;
    const scrollThreshold = 30;

    const checkScroll = () => {
      const scrollPosition = window.scrollY;
      const documentHeight = document.documentElement.scrollHeight - window.innerHeight;
      const scrollPercentage = (scrollPosition / documentHeight) * 100;

      if (scrollPercentage >= scrollThreshold && !this.hasShown) {
        this.container.style.display = 'block';
        setTimeout(() => {
          this.container.classList.add('visible');
        }, 10);
        this.hasShown = true;
      }

      if (scrollPosition < 100 && scrollPosition < lastScrollPosition) {
        this.container.classList.remove('visible');
        setTimeout(() => {
          this.container.style.display = 'none';
        }, 300);
        this.hasShown = false;
      }

      lastScrollPosition = scrollPosition;
    };

    checkScroll();
    window.addEventListener('scroll', checkScroll);
  }

  openModal() {
    this.modal.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  closeModal() {
    if (this.isLoading) return;
    
    this.modal.classList.remove('active');
    document.body.style.overflow = '';
    this.button.style.transform = 'scale(0.95)';
    setTimeout(() => {
      this.button.style.transform = '';
      this.form.reset();
      document.getElementById('recommendations-container').innerHTML = '';
    }, 200);
  }

  async handleSubmit(e) {
    e.preventDefault();
    if (this.isLoading) return;

    const submitButton = this.form.querySelector('.submit-button');
    const buttonText = submitButton.querySelector('.button-text');
    const originalText = buttonText.textContent;
    const recommendationsContainer = document.getElementById('recommendations-container');
    
    this.isLoading = true;
    submitButton.disabled = true;
    buttonText.textContent = 'Finding your perfect match...';
    recommendationsContainer.innerHTML = '<div class="loading">Analyzing your preferences with AI...</div>';

    const formData = new FormData(this.form);
    const userQuery = {
      preferences: {
        price_range: formData.get('price_range'),
        category: formData.get('category'),
        keywords: formData.get('keywords').split(',').map(k => k.trim()).filter(k => k)
      },
      context: {
        shop_domain: this.shopDomain,
        current_product: this.productId,
        time_of_day: new Date().getHours(),
        device_type: /Mobile|Android|iPhone/i.test(navigator.userAgent) ? 'mobile' : 'desktop',
        user_preferences: {
          price_sensitivity: formData.get('price_range').startsWith('0-') ? 'high' : 'moderate',
          style_preferences: formData.get('keywords').toLowerCase().includes('modern') ? 'modern' : 'classic'
        }
      }
    };

    try {
      console.log('Sending request to:', `${this.apiUrl}/api/mistral/recommend`);
      console.log('Request data:', userQuery);

      const response = await fetch(`${this.apiUrl}/api/mistral/recommend`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-Shop-Domain': this.shopDomain
        },
        body: JSON.stringify(userQuery),
        credentials: 'include'
      });

      console.log('Response status:', response.status);
      const responseText = await response.text();
      console.log('Response text:', responseText);

      if (!response.ok) {
        throw new Error(`Failed to get recommendations: ${response.status} ${responseText}`);
      }

      const result = JSON.parse(responseText);
      console.log('Parsed response:', result);

      if (result.recommendations && result.recommendations.length > 0) {
        this.displayRecommendations(result.recommendations);
      } else {
        recommendationsContainer.innerHTML = `
          <div class="no-results">
            <p>No matching products found for your criteria.</p>
            <p>Try adjusting your preferences or using different keywords.</p>
          </div>
        `;
      }
    } catch (error) {
      console.error('Error getting recommendations:', error);
      recommendationsContainer.innerHTML = `
        <div class="error-message">
          <p>Sorry, we couldn't get recommendations at this time.</p>
          <p>Please try again later.</p>
          <small class="error-details">${error.message}</small>
        </div>
      `;
    } finally {
      this.isLoading = false;
      submitButton.disabled = false;
      buttonText.textContent = originalText;
    }
  }

  displayRecommendations(recommendations) {
    const container = document.getElementById('recommendations-container');
    if (!recommendations || recommendations.length === 0) {
      container.innerHTML = `
        <div class="no-results">
          <p>No matching products found.</p>
          <p>Try adjusting your preferences.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = recommendations.map(rec => {
      const matchScore = Math.round((rec.confidence_score || 0.7) * 100);
      
      return `
        <div class="product-card">
          <div class="product-image-container">
            ${rec.product.image_url ? 
              `<img src="${rec.product.image_url}" alt="${rec.product.title}" loading="lazy">` :
              '<div class="no-image">No image available</div>'
            }
          </div>
          <span class="match-score">${matchScore}% Match</span>
          <h3>${rec.product.title}</h3>
          <p class="price">£${rec.product.price}</p>
          <div class="reasons">
            ${rec.explanation.split('\n').map(reason => `
              <p class="reason">✓ ${reason.trim()}</p>
            `).join('')}
          </div>
          <a href="${rec.product.url}" class="view-product" target="_blank">View Details</a>
        </div>
      `;
    }).join('');
  }
}

new SmartAdvisor(); 