// Samsung One UI inspired animations
document.addEventListener('DOMContentLoaded', function() {
    // Initialize smooth page transitions
    initPageTransitions();
    
    // Initialize card hover effects
    initCardHoverEffects();
    
    // Initialize button effects
    initButtonEffects();
    
    // Initialize progress bar animations
    initProgressBars();
    
    // Initialize logo animation if exists
    if (document.querySelector('.logo-container')) {
        animateLogo();
    }
});

// Smooth page transitions
function initPageTransitions() {
    const links = document.querySelectorAll('a:not([target="_blank"]):not([href^="#"]):not([href^="javascript:"])');
    
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            // Skip transition if user is holding modifier keys
            if (e.metaKey || e.ctrlKey || e.shiftKey) return;
            
            const href = this.getAttribute('href');
            
            // Skip if link is to the same page or is an anchor
            if (href === window.location.pathname || href.startsWith('#')) return;
            
            e.preventDefault();
            
            // Start exit animation
            document.body.classList.add('page-exit');
            
            // Navigate after animation completes
            setTimeout(() => {
                window.location.href = href;
            }, 300);
        });
    });
    
    // Add entrance animation when page loads
    window.addEventListener('pageshow', function(e) {
        if (e.persisted) {
            document.body.classList.remove('page-exit');
        }
        document.body.classList.add('page-enter');
        setTimeout(() => {
            document.body.classList.remove('page-enter');
        }, 500);
    });
}

// Card hover effects
function initCardHoverEffects() {
    const cards = document.querySelectorAll('.card, .feature-card, .result-card, .comment-card, .dork-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
            this.style.boxShadow = '0 8px 16px rgba(0, 0, 0, 0.15)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.boxShadow = '';
        });
    });
}

// Button effects
function initButtonEffects() {
    const buttons = document.querySelectorAll('.btn');
    
    buttons.forEach(button => {
        // Add ripple effect on click
        button.addEventListener('click', function(e) {
            const x = e.clientX - this.getBoundingClientRect().left;
            const y = e.clientY - this.getBoundingClientRect().top;
            
            const ripple = document.createElement('span');
            ripple.className = 'ripple';
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;
            
            this.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
        
        // Add hover animation
        button.addEventListener('mouseenter', function() {
            if (this.classList.contains('btn-primary')) {
                this.style.transform = 'translateY(-2px)';
                this.style.boxShadow = '0 4px 8px rgba(26, 115, 232, 0.3)';
            } else {
                this.style.transform = 'translateY(-2px)';
            }
        });
        
        button.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.boxShadow = '';
        });
    });
}

// Progress bar animations
function initProgressBars() {
    const progressBars = document.querySelectorAll('.progress-bar');
    
    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const targetWidth = entry.target.getAttribute('aria-valuenow') + '%';
                    setTimeout(() => {
                        entry.target.style.width = targetWidth;
                    }, 200);
                    observer.unobserve(entry.target);
                }
            });
        });
        
        progressBars.forEach(bar => {
            const currentWidth = bar.style.width;
            bar.style.width = '0%';
            observer.observe(bar);
        });
    }
}

// Logo animation
function animateLogo() {
    const logoContainer = document.querySelector('.logo-container');
    const logo = document.querySelector('.main-logo');
    
    if (logo && logoContainer) {
        logoContainer.addEventListener('mouseenter', function() {
            logo.style.transform = 'rotate(5deg) scale(1.05)';
        });
        
        logoContainer.addEventListener('mouseleave', function() {
            logo.style.transform = '';
        });
    }
}

// Add CSS animations to the document
const styleSheet = document.createElement('style');
styleSheet.textContent = `
    /* Page transitions */
    .page-exit {
        opacity: 0;
        transform: translateY(10px);
        transition: opacity 300ms ease, transform 300ms ease;
    }
    
    .page-enter {
        opacity: 0;
        transform: translateY(10px);
        animation: pageEnter 500ms ease forwards;
    }
    
    @keyframes pageEnter {
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    /* Button ripple effect */
    .ripple {
        position: absolute;
        border-radius: 50%;
        background-color: rgba(255, 255, 255, 0.4);
        transform: scale(0);
        animation: ripple 600ms linear;
        pointer-events: none;
    }
    
    @keyframes ripple {
        to {
            transform: scale(2.5);
            opacity: 0;
        }
    }
    
    /* Smooth hover transitions */
    .btn, .card, .feature-card, .result-card, .comment-card, .dork-card {
        transition: transform 300ms cubic-bezier(0.4, 0, 0.2, 1), 
                    box-shadow 300ms cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    /* Progress bar animations */
    .progress-bar {
        transition: width 800ms cubic-bezier(0.1, 0.9, 0.2, 1);
    }
    
    /* Logo animations */
    .main-logo {
        transition: transform 300ms cubic-bezier(0.4, 0, 0.2, 1);
    }
`;

document.head.appendChild(styleSheet);
