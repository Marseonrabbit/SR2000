// Samsung One UI-style animations and interactions
document.addEventListener('DOMContentLoaded', function() {
    // Add smooth scroll behavior
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                window.scrollTo({
                    top: target.offsetTop,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Add ripple effect to buttons
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const ripple = document.createElement('span');
            ripple.style.position = 'absolute';
            ripple.style.width = '1px';
            ripple.style.height = '1px';
            ripple.style.backgroundColor = 'rgba(255, 255, 255, 0.7)';
            ripple.style.borderRadius = '50%';
            ripple.style.transform = 'scale(0)';
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;
            ripple.style.pointerEvents = 'none';
            
            this.appendChild(ripple);
            
            // Animate the ripple
            ripple.animate(
                [
                    { transform: 'scale(0)', opacity: 1 },
                    { transform: 'scale(100)', opacity: 0 }
                ],
                {
                    duration: 600,
                    easing: 'cubic-bezier(0.4, 0, 0.2, 1)'
                }
            );
            
            // Remove the ripple after animation completes
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });

    // Form validation animations
    const formInputs = document.querySelectorAll('.form-control');
    formInputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.closest('.input-group')?.classList.add('input-focus');
        });
        
        input.addEventListener('blur', function() {
            this.closest('.input-group')?.classList.remove('input-focus');
        });
    });

    // Animate elements when they come into view
    const animateOnScroll = function() {
        const elements = document.querySelectorAll('.feature-item, .tool-card, .info-card, .comment-card');
        
        elements.forEach(element => {
            const elementPosition = element.getBoundingClientRect().top;
            const windowHeight = window.innerHeight;
            
            if (elementPosition < windowHeight - 50) {
                // Add animation class if element is in viewport
                element.classList.add('animate-fade-in-up');
                // Remove the element from the observer once animated
                observer.unobserve(element);
            }
        });
    };

    // Set up Intersection Observer for scroll animations
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-fade-in-up');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    // Observe elements for animation
    document.querySelectorAll('.feature-item, .tool-card, .info-card, .comment-card, .osint-category, .dorks-category').forEach(el => {
        observer.observe(el);
    });

    // Initial check on page load
    animateOnScroll();

    // Handle alerts
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert.querySelector('.btn-close')) {
                alert.querySelector('.btn-close').click();
            }
        }, 5000);
    });

    // Progressbar animations
    const progressBars = document.querySelectorAll('.progress-bar');
    progressBars.forEach(bar => {
        const targetWidth = bar.style.width || bar.getAttribute('aria-valuenow') + '%';
        bar.style.width = '0%';
        
        setTimeout(() => {
            bar.style.width = targetWidth;
        }, 300);
    });

    // Toggle navigation
    const navToggler = document.querySelector('.navbar-toggler');
    if (navToggler) {
        navToggler.addEventListener('click', function() {
            document.querySelector('body').classList.toggle('nav-open');
        });
    }
});

// Progress bar animation for batch processing
function animateProgressBar(jobId) {
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    
    if (!progressFill || !progressText) return;
    
    function updateProgress() {
        fetch(`/progress/${jobId}`)
            .then(response => response.json())
            .then(data => {
                // Smooth animation for progress updates
                const currentWidth = parseInt(progressFill.style.width || '0');
                const targetWidth = data.progress;
                
                // Animate from current to target
                if (currentWidth < targetWidth) {
                    let width = currentWidth;
                    const interval = setInterval(() => {
                        width++;
                        progressFill.style.width = width + '%';
                        progressText.innerText = width + '%';
                        
                        if (width >= targetWidth) {
                            clearInterval(interval);
                        }
                    }, 20);
                }
                
                // Update message with fade animation
                const messageElement = document.getElementById('message');
                if (messageElement && messageElement.innerText !== data.message) {
                    messageElement.style.opacity = '0';
                    setTimeout(() => {
                        messageElement.innerText = data.message;
                        messageElement.style.opacity = '1';
                    }, 300);
                }
                
                // Handle completion
                if (data.status === 'Completed') {
                    document.getElementById('downloadLink').href = '/download/' + jobId;
                    new bootstrap.Modal(document.getElementById('completionModal')).show();
                } else if (data.status === 'Canceled') {
                    document.getElementById('progress-bar').style.display = 'none';
                    document.getElementById('message').innerHTML = '<i class="fas fa-ban text-warning"></i> Analysis has been canceled.';
                } else if (data.status === 'Error') {
                    document.getElementById('message').innerHTML = '<i class="fas fa-exclamation-triangle text-danger"></i> ' + data.message;
                } else {
                    setTimeout(updateProgress, 1000);
                }
            })
            .catch(error => {
                console.error('Error fetching progress:', error);
                setTimeout(updateProgress, 1000);
            });
    }
    
    updateProgress();
}

// Copy to clipboard functionality
function copyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    // Show a small toast notification
    const toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.textContent = 'Copied to clipboard!';
    toast.style.position = 'fixed';
    toast.style.bottom = '20px';
    toast.style.left = '50%';
    toast.style.transform = 'translateX(-50%)';
    toast.style.backgroundColor = '#333';
    toast.style.color = 'white';
    toast.style.padding = '10px 20px';
    toast.style.borderRadius = '5px';
    toast.style.zIndex = '1000';
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    
    document.body.appendChild(toast);
    
    // Fade in
    setTimeout(() => {
        toast.style.opacity = '1';
    }, 10);
    
    // Fade out and remove
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 2000);
}
