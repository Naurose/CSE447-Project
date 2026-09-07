const API_URL = 'http://localhost:5000/api';

// Auth State
const isAuthenticated = () => !!localStorage.getItem('token');
const getUser = () => JSON.parse(localStorage.getItem('user'));
const isAdmin = () => {
    const u = getUser();
    return !!(u && u.role === 'admin');
};
const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('lastActivityTime');
    window.location.href = 'index.html';
};

// Headers
const getHeaders = () => ({
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${localStorage.getItem('token')}`
});

// Toast Notification
const showToast = (message) => {
    const toast = document.createElement('div');
    toast.className = 'toast show';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
};

// update Navbar
const updateNavbar = () => {
    // "Full Navbar" layout used by Store, Dashboard, Cart, etc.
    const authLinks = document.getElementById('authLinks');
    if (!authLinks) return;

    // Helper to check for active state
    const isActive = (page) => {
        const path = window.location.pathname;
        if (page === 'index' && (path.endsWith('index.html') || path.endsWith('/'))) return 'active';
        return path.includes(page + '.html') ? 'active' : '';
    };

    if (isAuthenticated()) {
        const user = getUser();
        const adminBadge = isAdmin() ? ' <span style="background: #ff0050; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-left: 4px;">ADMIN</span>' : '';
        // Standard "Full" authenticated menu
        authLinks.innerHTML = `
            <a href="newsfeed.html" class="nav-link ${isActive('newsfeed')}">News</a>
            <a href="store.html" class="nav-link ${isActive('store')}">Store</a>
            <a href="dashboard.html" class="nav-link ${isActive('dashboard')}">Library</a>
            <a href="cart.html" class="nav-link ${isActive('cart')}">Cart</a>
            <a href="profile.html" class="nav-link profile-link ${isActive('profile')}">${user.username}${adminBadge}</a>
            <a href="#" onclick="logout()" class="btn btn-secondary">Logout</a>
        `;
    } else {
        // Standard unauthenticated menu (Login/Register)
        // Landing page logic
        const path = window.location.pathname;
        const isLanding = path.endsWith('index.html') || path.endsWith('/') || path.endsWith('Gamevault/') || path.endsWith('Gamevault');
        const isAuthPage = path.endsWith('login.html') || path.endsWith('register.html');

        if (isLanding) {
            authLinks.innerHTML = `
                <a href="newsfeed.html" class="nav-link ${isActive('newsfeed')}">News</a>
                <a href="store.html" class="nav-link ${isActive('store')}">Store</a>
                <span class="user-greeting">Hello, Gamer</span>
            `;
        } else if (isAuthPage) {
            authLinks.innerHTML = `
                <a href="newsfeed.html" class="nav-link ${isActive('newsfeed')}">News</a>
                <a href="store.html" class="nav-link ${isActive('store')}">Store</a>
            `;
        } else {
            authLinks.innerHTML = `
                <a href="newsfeed.html" class="nav-link ${isActive('newsfeed')}">News</a>
                <a href="store.html" class="nav-link ${isActive('store')}">Store</a>
                <a href="login.html" class="btn btn-secondary">Login</a>
                <a href="register.html" class="btn btn-primary">Join Now</a>
            `;
        }
    }

};

// API Functions
const api = {
    getGames: async (params = {}) => {
        const queryString = new URLSearchParams(params).toString();
        const res = await fetch(`${API_URL}/games?${queryString}`);
        return res.json();
    },
    login: async (email, password) => {
        const res = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (res.ok && data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            localStorage.setItem('lastActivityTime', Date.now().toString());
        }
        return data;
    },
    loginRequest: async (email, password) => {
        const res = await fetch(`${API_URL}/auth/login-request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        return res.json();
    },
    loginVerify: async (email, otp) => {
        const res = await fetch(`${API_URL}/auth/login-verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, otp })
        });
        const data = await res.json();
        if (res.ok && data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            localStorage.setItem('lastActivityTime', Date.now().toString());
        }
        return data;
    },
    register: async (userData) => {
        const res = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });
        return res.json();
    },
    registerRequest: async (userData) => {
        const res = await fetch(`${API_URL}/auth/register-request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });
        return res.json();
    },
    registerVerify: async (verifyPayload) => {
        const res = await fetch(`${API_URL}/auth/register-verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(verifyPayload)
        });
        const data = await res.json();
        if (res.ok && data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            localStorage.setItem('lastActivityTime', Date.now().toString());
        }
        return data;
    },
    resendOtp: async (email, purpose = 'login') => {
        const res = await fetch(`${API_URL}/auth/resend-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, purpose })
        });
        return res.json();
    },
    addToCart: async (gameId, type = 'buy', rentDuration = null) => {
        if (!isAuthenticated()) {
            window.location.href = 'login.html';
            return;
        }
        const user = getUser();
        const payload = { userId: user.id, gameId, type };
        if (type === 'rent' && rentDuration) {
            payload.rentDuration = rentDuration;
        }

        const res = await fetch(`${API_URL}/cart`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        showToast(data.message);
    }
};

// ==========================================
// OTP INPUT GRID HELPERS & UTILITIES
// ==========================================

let resendTimerInterval = null;

const startResendTimer = (seconds = 60) => {
    stopResendTimer();
    let remaining = seconds;

    const timerTextContainer = document.getElementById('resendTimerText');
    const timerCountEl = document.getElementById('timerCount');
    const resendBtn = document.getElementById('btnResendOtp');

    if (timerTextContainer) timerTextContainer.style.display = 'inline';
    if (resendBtn) resendBtn.style.display = 'none';
    if (timerCountEl) timerCountEl.textContent = remaining;

    resendTimerInterval = setInterval(() => {
        remaining--;
        if (timerCountEl) timerCountEl.textContent = remaining;

        if (remaining <= 0) {
            stopResendTimer();
            if (timerTextContainer) timerTextContainer.style.display = 'none';
            if (resendBtn) resendBtn.style.display = 'inline-block';
        }
    }, 1000);
};

const stopResendTimer = () => {
    if (resendTimerInterval) {
        clearInterval(resendTimerInterval);
        resendTimerInterval = null;
    }
};

const setupOtpInputGrid = (gridId, onComplete) => {
    const container = document.getElementById(gridId);
    if (!container) return;

    const inputs = container.querySelectorAll('.otp-box');

    inputs.forEach((input, index) => {
        // Prevent duplicate listeners
        const newInput = input.cloneNode(true);
        input.parentNode.replaceChild(newInput, input);
    });

    const refreshedInputs = container.querySelectorAll('.otp-box');

    refreshedInputs.forEach((input, index) => {
        // Focus first box
        if (index === 0) {
            setTimeout(() => input.focus(), 100);
        }

        // Input event (digit typed or pasted)
        newInputHandler(input, index, refreshedInputs, gridId, onComplete);
    });
};

const newInputHandler = (input, index, inputs, gridId, onComplete) => {
    input.addEventListener('focus', () => {
        input.select();
    });

    input.addEventListener('input', (e) => {
        const val = input.value;
        if (val) {
            input.classList.add('filled');
            if (index < inputs.length - 1) {
                inputs[index + 1].focus();
            }
            if (onComplete && getOtpValue(gridId).length === 6) {
                onComplete();
            }
        } else {
            input.classList.remove('filled');
        }
    });

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !input.value && index > 0) {
            inputs[index - 1].focus();
            inputs[index - 1].value = '';
            inputs[index - 1].classList.remove('filled');
        } else if (e.key === 'ArrowLeft' && index > 0) {
            inputs[index - 1].focus();
        } else if (e.key === 'ArrowRight' && index < inputs.length - 1) {
            inputs[index + 1].focus();
        }
    });

    input.addEventListener('paste', (e) => {
        e.preventDefault();
        const pastedData = (e.clipboardData || window.clipboardData).getData('text').trim();
        const digits = pastedData.replace(/\D/g, '').slice(0, 6);

        if (digits.length > 0) {
            digits.split('').forEach((char, i) => {
                if (inputs[i]) {
                    inputs[i].value = char;
                    inputs[i].classList.add('filled');
                }
            });

            const nextIndex = Math.min(digits.length, inputs.length - 1);
            inputs[nextIndex].focus();

            if (digits.length === 6 && onComplete) {
                onComplete();
            }
        }
    });
};

const getOtpValue = (gridId) => {
    const container = document.getElementById(gridId);
    if (!container) return '';
    const inputs = container.querySelectorAll('.otp-box');
    let code = '';
    inputs.forEach(input => code += input.value.trim());
    return code;
};

const clearOtpGrid = (gridId) => {
    const container = document.getElementById(gridId);
    if (!container) return;
    const inputs = container.querySelectorAll('.otp-box');
    inputs.forEach(input => {
        input.value = '';
        input.classList.remove('filled');
    });
    if (inputs[0]) inputs[0].focus();
};


// Rent Modal Logic
const openRentModal = (gameId, basePrice, title) => {
    // Check if modal exists, if not create it
    let modalOverlay = document.getElementById('rentModalOverlay');
    if (!modalOverlay) {
        modalOverlay = document.createElement('div');
        modalOverlay.id = 'rentModalOverlay';
        modalOverlay.className = 'rent-modal-overlay';
        modalOverlay.innerHTML = `
            <div class="rent-modal">
                <h2 id="rentModalTitle" class="section-title" style="margin-bottom: 1rem; font-size: 1.5rem;">Rent Game</h2>
                <p>Select rental duration:</p>
                <div class="rent-options">
                    <div class="rent-option selected" onclick="selectRentOption(7)">
                        <h4>7 Days</h4>
                        <p class="rent-price" id="price7"></p>
                    </div>
                    <div class="rent-option" onclick="selectRentOption(14)">
                        <h4>14 Days</h4>
                        <p class="rent-price" id="price14"></p>
                    </div>
                    <div class="rent-option" onclick="selectRentOption(30)">
                        <h4>30 Days</h4>
                        <p class="rent-price" id="price30"></p>
                    </div>
                </div>
                <div style="display: flex; gap: 1rem; justify-content: flex-end;">
                    <button class="btn btn-secondary" onclick="closeRentModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="confirmRent()">Confirm Rent</button>
                </div>
            </div>
        `;
        document.body.appendChild(modalOverlay);
    }

    // Update Content
    document.getElementById('rentModalTitle').textContent = `Rent ${title}`;
    
    // Calculate Prices
    const p7 = parseFloat(basePrice);
    const p14 = (p7 * 1.8).toFixed(2);
    const p30 = (p7 * 3.5).toFixed(2);

    document.getElementById('price7').textContent = `$${p7.toFixed(2)}`;
    document.getElementById('price14').textContent = `$${p14}`;
    document.getElementById('price30').textContent = `$${p30}`;

    // Store state
    window.currentRentGameId = gameId;
    window.currentRentDuration = 7; // Default
    
    // Reset selection visually
    document.querySelectorAll('.rent-option').forEach(el => el.classList.remove('selected'));
    document.querySelector('.rent-option').classList.add('selected'); // First one

    // Show
    modalOverlay.style.display = 'flex';
};

const closeRentModal = () => {
    const modal = document.getElementById('rentModalOverlay');
    if (modal) modal.style.display = 'none';
};

const selectRentOption = (days) => {
    window.currentRentDuration = days;
    document.querySelectorAll('.rent-option').forEach((el, index) => {
        el.classList.remove('selected');
        const optionDays = [7, 14, 30][index];
        if (optionDays === days) el.classList.add('selected');
    });
};

const confirmRent = () => {
    if (window.currentRentGameId) {
        api.addToCart(window.currentRentGameId, 'rent', window.currentRentDuration);
        closeRentModal();
    }
};

// Global expose for onclick
// Launch Modal Logic
const openLaunchModal = (title, image) => {
    let modal = document.getElementById('launchModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'launchModal';
        modal.className = 'launch-modal-overlay';
        modal.innerHTML = `
            <div class="launch-modal">
                <img id="launchImage" class="launch-image" src="" alt="Cover">
                <h1 id="launchTitle" style="font-size: 2.5rem; margin-bottom: 0.5rem;"></h1>
                <div class="launch-status">
                    <div class="launch-spinner"></div>
                    Launching...
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    document.getElementById('launchImage').src = image;
    document.getElementById('launchTitle').textContent = title;
    
    modal.style.display = 'flex';

    // Auto close after 3 seconds
    setTimeout(() => {
        modal.style.display = 'none';
    }, 4000); // 4 seconds for full effect
};

// Star Rating Helper
const getStarDisplayHTML = (rating, fontSize = '1rem') => {
    const r = parseFloat(rating) || 0;
    const percentage = (r / 5) * 100;
    
    return `
        <div class="star-rating-display" style="font-size: ${fontSize};" title="${r.toFixed(1)}/5">
            <div class="star-rating-display-back">★★★★★</div>
            <div class="star-rating-display-front" style="width: ${percentage}%">★★★★★</div>
        </div>
    `;
};

// ==========================================
// IDLE SESSION TIMEOUT LOGIC
// ==========================================
const IDLE_TIMEOUT_MS = 2 * 60 * 1000; // 2 minutes in milliseconds
let idleCheckInterval = null;
let lastThrottleTime = 0;

const resetIdleTimer = () => {
    if (!isAuthenticated()) return;
    const now = Date.now();
    // Throttle localStorage updates to avoid high-frequency write overhead (max once per sec)
    if (now - lastThrottleTime > 1000) {
        lastThrottleTime = now;
        localStorage.setItem('lastActivityTime', now.toString());
    }
};

const showSessionTimeoutModal = () => {
    let modal = document.getElementById('sessionTimeoutModalOverlay');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'sessionTimeoutModalOverlay';
        modal.className = 'session-timeout-overlay';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        `;
        modal.innerHTML = `
            <div class="session-timeout-modal" style="
                background: #18181b;
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 16px;
                padding: 2.5rem;
                max-width: 420px;
                width: 90%;
                text-align: center;
                box-shadow: 0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(0, 242, 234, 0.2);
            ">
                <div style="font-size: 3.5rem; margin-bottom: 1rem;">⚠️</div>
                <h2 style="font-size: 1.8rem; font-weight: 800; margin-bottom: 0.8rem; color: #ff0050; font-family: sans-serif;">Session Timeout</h2>
                <p style="color: #cbd5e1; margin-bottom: 1.8rem; font-size: 1rem; line-height: 1.6; font-family: sans-serif;">
                    You have been logged out due to inactivity for more than 2 minutes.
                </p>
                <button class="btn btn-primary" style="
                    width: 100%;
                    padding: 0.8rem 1.5rem;
                    border-radius: 50px;
                    border: none;
                    background: #00f2ea;
                    color: #000;
                    font-weight: 700;
                    font-size: 0.95rem;
                    cursor: pointer;
                    text-transform: uppercase;
                    transition: transform 0.2s;
                " onclick="redirectToLogin()">LOG IN AGAIN</button>
            </div>
        `;
        document.body.appendChild(modal);
    } else {
        modal.style.display = 'flex';
    }
};

const redirectToLogin = () => {
    const modal = document.getElementById('sessionTimeoutModalOverlay');
    if (modal) modal.style.display = 'none';
    window.location.href = 'login.html';
};

const triggerSessionTimeout = () => {
    // Clear auth credentials from storage
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('lastActivityTime');

    // Update navbar to unauthenticated state if element exists
    updateNavbar();

    // Show session timeout popup modal
    showSessionTimeoutModal();
};

const checkIdleTimeout = () => {
    if (!isAuthenticated()) return;

    const lastActivityStr = localStorage.getItem('lastActivityTime');
    if (!lastActivityStr) {
        resetIdleTimer();
        return;
    }

    const lastActivity = parseInt(lastActivityStr, 10);
    const now = Date.now();

    if (now - lastActivity >= IDLE_TIMEOUT_MS) {
        triggerSessionTimeout();
    }
};

const initIdleSessionTimeout = () => {
    const activityEvents = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'click'];
    activityEvents.forEach(evt => {
        window.addEventListener(evt, resetIdleTimer, { passive: true });
    });

    if (isAuthenticated() && !localStorage.getItem('lastActivityTime')) {
        localStorage.setItem('lastActivityTime', Date.now().toString());
    }

    if (idleCheckInterval) clearInterval(idleCheckInterval);
    idleCheckInterval = setInterval(checkIdleTimeout, 1000);
};

window.getStarDisplayHTML = getStarDisplayHTML;
window.openRentModal = openRentModal;
window.closeRentModal = closeRentModal;
window.selectRentOption = selectRentOption;
window.confirmRent = confirmRent;
window.openLaunchModal = openLaunchModal; // play animation function
window.setupOtpInputGrid = setupOtpInputGrid;
window.getOtpValue = getOtpValue;
window.clearOtpGrid = clearOtpGrid;
window.startResendTimer = startResendTimer;
window.stopResendTimer = stopResendTimer;
window.showToast = showToast;
window.isAuthenticated = isAuthenticated;
window.getUser = getUser;
window.isAdmin = isAdmin;
window.logout = logout;
window.api = api; // api is global for inline onclicks
window.redirectToLogin = redirectToLogin;
window.initIdleSessionTimeout = initIdleSessionTimeout;
window.resetIdleTimer = resetIdleTimer;

document.addEventListener('DOMContentLoaded', () => {
    updateNavbar();
    initIdleSessionTimeout();
});


