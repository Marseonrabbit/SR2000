// OSINT Framework - based on lockfale/osint-framework
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the OSINT framework categories and tools
    initOsintFramework();
    
    // Set up category toggle functionality
    document.querySelectorAll('.osint-category-header').forEach(header => {
        header.addEventListener('click', function() {
            const category = this.parentElement;
            category.classList.toggle('active');
            
            // Animate the chevron icon
            const icon = this.querySelector('i');
            if (category.classList.contains('active')) {
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
            } else {
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
            }
        });
    });
    
    // Search functionality
    const searchInput = document.getElementById('osint-search');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            filterOsintTools(searchTerm);
        });
    }
});

function initOsintFramework() {
    // This data is based on lockfale/osint-framework
    const osintData = [
        {
            category: "Username Analysis",
            tools: [
                {
                    name: "WhatsMyName",
                    url: "https://whatsmyname.app/",
                    description: "This tool allows you to enumerate usernames across many websites."
                },
                {
                    name: "Sherlock",
                    url: "https://github.com/sherlock-project/sherlock",
                    description: "Hunt down social media accounts by username across social networks."
                },
                {
                    name: "GHunt",
                    url: "https://github.com/mxrch/GHunt",
                    description: "Investigate Google accounts with emails."
                },
                {
                    name: "Namechk",
                    url: "https://namechk.com/",
                    description: "Check for usernames across multiple platforms."
                },
                {
                    name: "KnowEm",
                    url: "https://knowem.com/",
                    description: "Check for username and brand availability on social networks."
                }
            ]
        },
        {
            category: "Email Analysis",
            tools: [
                {
                    name: "Hunter.io",
                    url: "https://hunter.io/",
                    description: "Find email addresses associated with a domain."
                },
                {
                    name: "EmailRep",
                    url: "https://emailrep.io/",
                    description: "Simple email reputation lookup service."
                },
                {
                    name: "Have I Been Pwned",
                    url: "https://haveibeenpwned.com/",
                    description: "Check if your email has been compromised in a data breach."
                },
                {
                    name: "Email Checker",
                    url: "https://email-checker.net/",
                    description: "Verify email address existence and validity."
                },
                {
                    name: "Epieos",
                    url: "https://epieos.com/",
                    description: "Retrieve information linked to an email address."
                }
            ]
        },
        {
            category: "Domain & IP Analysis",
            tools: [
                {
                    name: "VirusTotal",
                    url: "https://www.virustotal.com/",
                    description: "Analyze suspicious domains, IPs, URLs, and files."
                },
                {
                    name: "Shodan",
                    url: "https://www.shodan.io/",
                    description: "Search engine for Internet-connected devices."
                },
                {
                    name: "Censys",
                    url: "https://censys.io/",
                    description: "Search engine for Internet devices, networks, and certificates."
                },
                {
                    name: "SecurityTrails",
                    url: "https://securitytrails.com/",
                    description: "Extensive DNS and domain data."
                },
                {
                    name: "DNSDumpster",
                    url: "https://dnsdumpster.com/",
                    description: "Free domain research tool that can discover hosts related to a domain."
                }
            ]
        },
        {
            category: "Social Media Analysis",
            tools: [
                {
                    name: "TweetDeck",
                    url: "https://tweetdeck.twitter.com/",
                    description: "Twitter dashboard for tracking and organizing tweets."
                },
                {
                    name: "Social Searcher",
                    url: "https://www.social-searcher.com/",
                    description: "Search engine for social media platforms."
                },
                {
                    name: "Twint",
                    url: "https://github.com/twintproject/twint",
                    description: "Advanced Twitter scraping tool without API limitations."
                },
                {
                    name: "Snoopza",
                    url: "https://snoopza.com/",
                    description: "Social media monitoring service."
                },
                {
                    name: "Instagram Explorer",
                    url: "https://www.osintcombine.com/instagram-explorer",
                    description: "Tool to explore Instagram data."
                }
            ]
        },
        {
            category: "Phone Number Analysis",
            tools: [
                {
                    name: "Phoneinfoga",
                    url: "https://github.com/sundowndev/phoneinfoga",
                    description: "Information gathering & OSINT framework for phone numbers."
                },
                {
                    name: "Truecaller",
                    url: "https://www.truecaller.com/",
                    description: "Caller ID and spam blocking app."
                },
                {
                    name: "NumLookup",
                    url: "https://numlookup.com/",
                    description: "Free reverse phone lookup service."
                },
                {
                    name: "CallerID Test",
                    url: "https://calleridtest.com/",
                    description: "Caller ID reputation and spam risk assessment."
                },
                {
                    name: "Sync.ME",
                    url: "https://sync.me/",
                    description: "Reverse phone lookup and caller ID app."
                }
            ]
        },
        {
            category: "Image & Geolocation Analysis",
            tools: [
                {
                    name: "Google Reverse Image Search",
                    url: "https://images.google.com/",
                    description: "Search by image to find similar images across the web."
                },
                {
                    name: "TinEye",
                    url: "https://tineye.com/",
                    description: "Reverse image search engine."
                },
                {
                    name: "Jeffrey's Image Metadata Viewer",
                    url: "http://exif.regex.info/exif.cgi",
                    description: "Extract metadata from images."
                },
                {
                    name: "PimEyes",
                    url: "https://pimeyes.com/",
                    description: "Reverse face search engine."
                },
                {
                    name: "Geoseer",
                    url: "https://www.geoseer.net/",
                    description: "Geospatial search engine."
                }
            ]
        },
        {
            category: "Breach & Leak Analysis",
            tools: [
                {
                    name: "Have I Been Pwned",
                    url: "https://haveibeenpwned.com/",
                    description: "Check if your data has been compromised in a data breach."
                },
                {
                    name: "DeHashed",
                    url: "https://dehashed.com/",
                    description: "Search for exposed credentials and leaks."
                },
                {
                    name: "Leak-Lookup",
                    url: "https://leak-lookup.com/",
                    description: "Search engine for data breaches."
                },
                {
                    name: "WeLeakInfo",
                    url: "https://weleakinfo.to/",
                    description: "Search for data in leaked databases."
                },
                {
                    name: "BreachDirectory",
                    url: "https://breachdirectory.org/",
                    description: "Check if your email or phone is in a data breach."
                }
            ]
        },
        {
            category: "Dark Web Analysis",
            tools: [
                {
                    name: "Tor Browser",
                    url: "https://www.torproject.org/",
                    description: "Browser for accessing the Tor network."
                },
                {
                    name: "DarkSearch",
                    url: "https://darksearch.io/",
                    description: "The first real dark web search engine."
                },
                {
                    name: "Ahmia",
                    url: "https://ahmia.fi/",
                    description: "Search engine for Tor hidden services."
                },
                {
                    name: "OnionScan",
                    url: "https://github.com/s-rah/onionscan",
                    description: "Investigate dark web sites for security issues."
                },
                {
                    name: "DarkOwl",
                    url: "https://www.darkowl.com/",
                    description: "Darknet content search and monitoring platform."
                }
            ]
        },
        {
            category: "Document & Metadata Analysis",
            tools: [
                {
                    name: "FOCA",
                    url: "https://github.com/ElevenPaths/FOCA",
                    description: "Tool to extract metadata and hidden information from documents."
                },
                {
                    name: "Metagoofil",
                    url: "https://github.com/laramies/metagoofil",
                    description: "Extract metadata from public documents."
                },
                {
                    name: "ExifTool",
                    url: "https://exiftool.org/",
                    description: "Read and write metadata in files."
                },
                {
                    name: "PDF Examiner",
                    url: "https://www.pdfexaminer.com/",
                    description: "Analyze PDF files for malicious content."
                },
                {
                    name: "Maltego",
                    url: "https://www.maltego.com/",
                    description: "Interactive data mining tool for link analysis."
                }
            ]
        }
    ];
    
    // Render OSINT Framework data
    const frameworkContainer = document.getElementById('osint-framework-container');
    if (frameworkContainer) {
        osintData.forEach(categoryData => {
            const categoryElement = document.createElement('div');
            categoryElement.className = 'osint-category mb-4';
            categoryElement.dataset.category = categoryData.category.toLowerCase();
            
            const categoryHeader = document.createElement('div');
            categoryHeader.className = 'osint-category-header';
            categoryHeader.innerHTML = `
                <h3>
                    <span>${categoryData.category}</span>
                    <i class="fas fa-chevron-down"></i>
                </h3>
            `;
            
            const categoryContent = document.createElement('div');
            categoryContent.className = 'osint-category-content';
            
            categoryData.tools.forEach(tool => {
                const toolElement = document.createElement('div');
                toolElement.className = 'osint-tool';
                toolElement.dataset.name = tool.name.toLowerCase();
                toolElement.dataset.description = tool.description.toLowerCase();
                
                toolElement.innerHTML = `
                    <a href="${tool.url}" target="_blank" rel="noopener noreferrer">
                        <span class="osint-tool-name">${tool.name}</span>
                    </a>
                    <p class="osint-tool-description">${tool.description}</p>
                `;
                
                categoryContent.appendChild(toolElement);
            });
            
            categoryElement.appendChild(categoryHeader);
            categoryElement.appendChild(categoryContent);
            frameworkContainer.appendChild(categoryElement);
        });
    }
}

function filterOsintTools(searchTerm) {
    const categories = document.querySelectorAll('.osint-category');
    
    categories.forEach(category => {
        const tools = category.querySelectorAll('.osint-tool');
        let hasVisibleTools = false;
        
        tools.forEach(tool => {
            const toolName = tool.dataset.name || '';
            const toolDescription = tool.dataset.description || '';
            const categoryName = category.dataset.category || '';
            
            const matchesSearch = 
                toolName.includes(searchTerm) || 
                toolDescription.includes(searchTerm) || 
                categoryName.includes(searchTerm);
            
            if (matchesSearch) {
                tool.style.display = 'block';
                hasVisibleTools = true;
            } else {
                tool.style.display = 'none';
            }
        });
        
        // Show/hide the entire category based on whether it has visible tools
        if (hasVisibleTools) {
            category.style.display = 'block';
            // Auto-expand categories with matches
            if (searchTerm.length > 0) {
                category.classList.add('active');
                const icon = category.querySelector('.osint-category-header i');
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
            }
        } else {
            category.style.display = 'none';
        }
    });
    
    // If search is cleared, collapse all categories
    if (searchTerm.length === 0) {
        categories.forEach(category => {
            category.classList.remove('active');
            const icon = category.querySelector('.osint-category-header i');
            icon.classList.remove('fa-chevron-up');
            icon.classList.add('fa-chevron-down');
        });
    }
}
