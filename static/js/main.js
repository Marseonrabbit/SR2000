document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltip
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Active navbar item
    highlightActiveNavItem();

    // Initialize copy buttons for Google Dorks
    initializeCopyButtons();

    // Initialize OSINT framework category toggles
    initializeOsintCategories();

    // Initialize animated elements
    initializeAnimations();

    // Initialize IP validation if on index page
    if (document.getElementById('ip-form')) {
        document.getElementById('ip-form').addEventListener('submit', validateIP);
    }
    
    // Initialize hash validation if on hash lookup page
    if (document.getElementById('hash-form')) {
        document.getElementById('hash-form').addEventListener('submit', validateHash);
    }
    
    // Initialize filter functionality for Google Dorks
    if (document.getElementById('dork-search')) {
        document.getElementById('dork-search').addEventListener('input', filterDorks);
    }
    
    // Initialize category filter for Google Dorks
    if (document.getElementById('dork-category-filter')) {
        document.getElementById('dork-category-filter').addEventListener('change', filterDorks);
    }
});

// Function to highlight active navbar item
function highlightActiveNavItem() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        const linkPath = link.getAttribute('href');
        if (currentPath === linkPath || 
            (linkPath !== '/' && currentPath.startsWith(linkPath))) {
            link.parentElement.classList.add('active');
        }
    });
}

// Function for IP validation
function validateIP(event) {
    const ipInput = document.getElementById('ip-input');
    const ip = ipInput.value.trim();
    
    // Regular expressions for validation
    const privateIPRegex = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.0\.0\.1$)/;
    const broadcastIPRegex = /^(\d{1,3}\.){3}255$/;
    const ipFormat = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    
    // Check if IP is in valid format
    if (!ipFormat.test(ip)) {
        event.preventDefault();
        showValidationError(ipInput, 'Please enter a valid IP address (e.g., 8.8.8.8)');
        return false;
    }
    
    // Check IP segments
    const segments = ip.match(ipFormat);
    if (segments) {
        for (let i = 1; i <= 4; i++) {
            if (parseInt(segments[i]) > 255) {
                event.preventDefault();
                showValidationError(ipInput, 'IP address segments cannot be greater than 255');
                return false;
            }
        }
    }
    
    // Check if private or broadcast IP
    if (privateIPRegex.test(ip) || broadcastIPRegex.test(ip)) {
        event.preventDefault();
        showValidationError(ipInput, 'Please enter a public IP address for analysis');
        return false;
    }
    
    return true;
}

// Function for hash validation
function validateHash(event) {
    const hashInput = document.getElementById('hash-input');
    const hash = hashInput.value.trim();
    
    // Regular expressions for common hash types
    const md5Regex = /^[a-fA-F0-9]{32}$/;
    const sha1Regex = /^[a-fA-F0-9]{40}$/;
    const sha256Regex = /^[a-fA-F0-9]{64}$/;
    
    if (!(md5Regex.test(hash) || sha1Regex.test(hash) || sha256Regex.test(hash))) {
        event.preventDefault();
        showValidationError(hashInput, 'Please enter a valid MD5, SHA-1, or SHA-256 hash');
        return false;
    }
    
    return true;
}

// Function to show validation error
function showValidationError(inputElement, message) {
    // Create or update error message
    let errorElement = inputElement.nextElementSibling;
    if (!errorElement || !errorElement.classList.contains('validation-error')) {
        errorElement = document.createElement('div');
        errorElement.className = 'validation-error text-danger mt-2';
        inputElement.parentNode.insertBefore(errorElement, inputElement.nextSibling);
    }
    
    errorElement.textContent = message;
    
    // Highlight input
    inputElement.classList.add('is-invalid');
    
    // Remove error after 5 seconds
    setTimeout(() => {
        if (errorElement && errorElement.parentNode) {
            errorElement.remove();
            inputElement.classList.remove('is-invalid');
        }
    }, 5000);
    
    // Or remove when user starts typing again
    inputElement.addEventListener('input', function() {
        if (errorElement && errorElement.parentNode) {
            errorElement.remove();
            inputElement.classList.remove('is-invalid');
        }
    }, { once: true });
}

// Initialize copy buttons for Google Dorks
function initializeCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const dorkQuery = this.parentElement.textContent.trim();
            navigator.clipboard.writeText(dorkQuery).then(() => {
                // Change button text temporarily
                const originalText = this.textContent;
                this.textContent = 'Copied!';
                setTimeout(() => {
                    this.textContent = originalText;
                }, 2000);
            });
        });
    });
}

// Initialize OSINT framework category toggles
function initializeOsintCategories() {
    const categoryTitles = document.querySelectorAll('.osint-category-title');
    
    categoryTitles.forEach(title => {
        title.addEventListener('click', function() {
            const category = this.parentElement;
            category.classList.toggle('osint-category-expanded');
        });
    });
}

// Filter functionality for Google Dorks
function filterDorks() {
    const searchTerm = document.getElementById('dork-search').value.toLowerCase();
    const categoryFilter = document.getElementById('dork-category-filter').value;
    const dorkCards = document.querySelectorAll('.dork-card');
    
    dorkCards.forEach(card => {
        const dorkQuery = card.querySelector('.dork-query').textContent.toLowerCase();
        const dorkDescription = card.querySelector('.dork-description').textContent.toLowerCase();
        const dorkCategory = card.querySelector('.dork-category').textContent.toLowerCase();
        
        const matchesSearch = dorkQuery.includes(searchTerm) || 
                               dorkDescription.includes(searchTerm);
        
        const matchesCategory = categoryFilter === 'all' || 
                               dorkCategory === categoryFilter.toLowerCase();
        
        if (matchesSearch && matchesCategory) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

// Initialize animations
function initializeAnimations() {
    const animatedElements = document.querySelectorAll('.fade-in, .slide-in-up, .pulse');
    
    // Check if IntersectionObserver is supported
    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.animationPlayState = 'running';
                    observer.unobserve(entry.target);
                }
            });
        });
        
        animatedElements.forEach(el => {
            el.style.animationPlayState = 'paused';
            observer.observe(el);
        });
    } else {
        // Fallback for browsers that don't support IntersectionObserver
        animatedElements.forEach(el => {
            el.style.animationPlayState = 'running';
        });
    }
}
