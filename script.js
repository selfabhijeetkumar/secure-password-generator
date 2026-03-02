/** ========================================
   Secure Password Generator - JavaScript
   ========================================
   
   A modular, beginner-friendly implementation with:
   - Cryptographically secure random generation using crypto.getRandomValues()
   - Password strength calculation with entropy
   - LocalStorage persistence
   - Full accessibility support
   - Password history (optional enhancement)
*/

// ========================================
// DOM Elements
// ========================================
const elements = {
    // Password display
    passwordDisplay: document.getElementById('password-display'),
    togglePasswordBtn: document.getElementById('toggle-password'),
    copyBtn: document.getElementById('copy-btn'),
    copyMessage: document.getElementById('copy-message'),
    
    // Controls
    lengthSlider: document.getElementById('length-slider'),
    lengthValue: document.getElementById('length-value'),
    generateBtn: document.getElementById('generate-btn'),
    regenerateBtn: document.getElementById('regenerate-btn'),
    
    // Character options
    uppercaseCheckbox: document.getElementById('uppercase'),
    lowercaseCheckbox: document.getElementById('lowercase'),
    numbersCheckbox: document.getElementById('numbers'),
    symbolsCheckbox: document.getElementById('symbols'),
    errorMessage: document.getElementById('error-message'),
    
    // Strength indicator
    strengthBar: document.getElementById('strength-bar'),
    strengthText: document.getElementById('strength-text'),
    entropyText: document.getElementById('entropy-text'),
    
    // Password history
    passwordHistory: document.getElementById('password-history'),
    clearHistoryBtn: document.getElementById('clear-history-btn')
};

// ========================================
// Character Sets
// ========================================
const characterSets = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

// ========================================
// State Management
// ========================================
let state = {
    password: '',
    isPasswordVisible: false,
    passwordHistory: []
};

// ========================================
// Cryptographically Secure Random Functions
// ========================================

/**
 * Generates a cryptographically secure random number
 * Uses crypto.getRandomValues() instead of Math.random()
 * @param {number} max - Maximum value (exclusive)
 * @returns {number} Random number between 0 and max-1
 */
function getSecureRandomNumber(max) {
    const array = new Uint32Array(1);
    crypto.getRandomValues(array);
    return array[0] % max;
}

/**
 * Get a random uppercase letter
 * @returns {string} Random uppercase letter
 */
function getRandomUppercase() {
    return characterSets.uppercase[getSecureRandomNumber(characterSets.uppercase.length)];
}

/**
 * Get a random lowercase letter
 * @returns {string} Random lowercase letter
 */
function getRandomLowercase() {
    return characterSets.lowercase[getSecureRandomNumber(characterSets.lowercase.length)];
}

/**
 * Get a random number
 * @returns {string} Random number as string
 */
function getRandomNumber() {
    return characterSets.numbers[getSecureRandomNumber(characterSets.numbers.length)];
}

/**
 * Get a random symbol
 * @returns {string} Random symbol
 */
function getRandomSymbol() {
    return characterSets.symbols[getSecureRandomNumber(characterSets.symbols.length)];
}

// ========================================
// Password Generation Core
// ========================================

/**
 * Collects all selected character types
 * @returns {Object} Object with selected character sets
 */
function getSelectedCharacterSets() {
    return {
        uppercase: elements.uppercaseCheckbox.checked,
        lowercase: elements.lowercaseCheckbox.checked,
        numbers: elements.numbersCheckbox.checked,
        symbols: elements.symbolsCheckbox.checked
    };
}

/**
 * Builds a string of all selected characters
 * @param {Object} selected - Object with boolean flags for each character type
 * @returns {string} Combined string of selected characters
 */
function buildCharacterPool(selected) {
    let pool = '';
    if (selected.uppercase) pool += characterSets.uppercase;
    if (selected.lowercase) pool += characterSets.lowercase;
    if (selected.numbers) pool += characterSets.numbers;
    if (selected.symbols) pool += characterSets.symbols;
    return pool;
}

/**
 * Generates a random password based on selected options
 * Uses crypto.getRandomValues() for cryptographic security
 * @returns {string|null} Generated password or null if no options selected
 */
function generatePassword() {
    const selected = getSelectedCharacterSets();
    const hasAnySelected = Object.values(selected).some(val => val);
    
    if (!hasAnySelected) {
        showError('Please select at least one character type');
        return null;
    }
    
    clearError();
    
    const length = parseInt(elements.lengthSlider.value, 10);
    const pool = buildCharacterPool(selected);
    
    if (pool.length === 0) {
        showError('No characters available for generation');
        return null;
    }
    
    let password = '';
    
    // Ensure at least one character from each selected type
    if (selected.uppercase) password += getRandomUppercase();
    if (selected.lowercase) password += getRandomLowercase();
    if (selected.numbers) password += getRandomNumber();
    if (selected.symbols) password += getRandomSymbol();
    
    // Fill the rest with random characters from the pool
    const remainingLength = length - password.length;
    for (let i = 0; i < remainingLength; i++) {
        password += pool[getSecureRandomNumber(pool.length)];
    }
    
    // Shuffle the password to avoid predictable patterns
    password = shuffleString(password);
    
    state.password = password;
    return password;
}

/**
 * Shuffles a string using Fisher-Yates algorithm
 * @param {string} str - String to shuffle
 * @returns {string} Shuffled string
 */
function shuffleString(str) {
    const array = str.split('');
    for (let i = array.length - 1; i > 0; i--) {
        const j = getSecureRandomNumber(i + 1);
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array.join('');
}

// ========================================
// Password Strength Calculation
// ========================================

/**
 * Calculates password entropy in bits
 * Entropy = length * log2(pool size)
 * @param {string} password - Password to analyze
 * @returns {number} Entropy in bits
 */
function calculateEntropy(password) {
    if (!password) return 0;
    
    const selected = getSelectedCharacterSets();
    let poolSize = 0;
    
    if (selected.uppercase) poolSize += 26;
    if (selected.lowercase) poolSize += 26;
    if (selected.numbers) poolSize += 10;
    if (selected.symbols) poolSize += characterSets.symbols.length;
    
    if (poolSize === 0) return 0;
    
    return password.length * Math.log2(poolSize);
}

/**
 * Determines password strength based on entropy
 * @param {number} entropy - Entropy in bits
 * @returns {Object} Strength level and description
 */
function getStrengthLevel(entropy) {
    if (entropy < 28) {
        return { level: 'weak', text: 'Weak' };
    } else if (entropy < 60) {
        return { level: 'medium', text: 'Medium' };
    } else {
        return { level: 'strong', text: 'Strong' };
    }
}

/**
 * Updates the strength indicator UI
 * @param {string} password - Password to analyze
 */
function updateStrengthIndicator(password) {
    const entropy = calculateEntropy(password);
    const strength = getStrengthLevel(entropy);
    
    // Update bar
    elements.strengthBar.className = 'strength-bar ' + strength.level;
    elements.strengthBar.setAttribute('aria-valuenow', 
        strength.level === 'weak' ? 33 : strength.level === 'medium' ? 66 : 100
    );
    
    // Update text
    elements.strengthText.textContent = strength.text;
    elements.strengthText.className = 'strength-text ' + strength.level;
    
    // Update entropy display
    elements.entropyText.textContent = password ? `${Math.round(entropy)} bits of entropy` : '';
}

// ========================================
// Copy to Clipboard
// ========================================

/**
 * Copies the current password to clipboard
 * Uses Clipboard API with fallback
 */
async function copyPassword() {
    if (!state.password) {
        showError('No password to copy');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(state.password);
        showCopyMessage('Password copied!');
    } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = state.password;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            showCopyMessage('Password copied!');
        } catch (fallbackErr) {
            showError('Failed to copy password');
        }
        
        document.body.removeChild(textArea);
    }
}

/**
 * Shows temporary copy confirmation message
 * @param {string} message - Message to display
 */
function showCopyMessage(message) {
    elements.copyMessage.textContent = message;
    elements.copyMessage.classList.add('visible');
    
    setTimeout(() => {
        elements.copyMessage.classList.remove('visible');
    }, 2000);
}

// ========================================
// Error Handling
// ========================================

/**
 * Shows error message to user
 * @param {string} message - Error message to display
 */
function showError(message) {
    elements.errorMessage.textContent = message;
    elements.errorMessage.classList.add('visible');
}

/**
 * Clears error message
 */
function clearError() {
    elements.errorMessage.classList.remove('visible');
    elements.errorMessage.textContent = '';
}

// ========================================
// Password History (Optional Enhancement)
// ========================================

/**
 * Adds password to history
 * @param {string} password - Password to add
 */
function addToHistory(password) {
    if (!password) return;
    
    // Add to beginning of array
    state.passwordHistory.unshift(password);
    
    // Keep only last 10 passwords
    if (state.passwordHistory.length > 10) {
        state.passwordHistory.pop();
    }
    
    renderHistory();
    saveSettings();
}

/**
 * Renders password history in the UI
 */
function renderHistory() {
    elements.passwordHistory.innerHTML = '';
    
    state.passwordHistory.forEach((password, index) => {
        const li = document.createElement('li');
        li.innerHTML = `
            <span>${password}</span>
            <button type="button" aria-label="Copy password ${index + 1}">📋</button>
        `;
        
        // Click to copy
        li.querySelector('button').addEventListener('click', async (e) => {
            e.stopPropagation();
            try {
                await navigator.clipboard.writeText(password);
                showCopyMessage('Copied from history!');
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        });
        
        // Click on history item to use it
        li.addEventListener('click', () => {
            elements.passwordDisplay.value = password;
            state.password = password;
            updateStrengthIndicator(password);
        });
        
        elements.passwordHistory.appendChild(li);
    });
}

/**
 * Clears password history
 */
function clearHistory() {
    state.passwordHistory = [];
    renderHistory();
    saveSettings();
}

// ========================================
// Show/Hide Password Toggle (Optional Enhancement)
// ========================================

/**
 * Toggles password visibility
 */
function togglePasswordVisibility() {
    state.isPasswordVisible = !state.isPasswordVisible;
    
    const newType = state.isPasswordVisible ? 'text' : 'password';
    elements.passwordDisplay.type = newType;
    
    // Update button label
    elements.togglePasswordBtn.setAttribute('aria-label',
        state.isPasswordVisible ? 'Hide password' : 'Show password'
    );
    elements.togglePasswordBtn.title = 
        state.isPasswordVisible ? 'Hide password' : 'Show password';
}

// ========================================
// Persistence (LocalStorage)
// ========================================

/**
 * Saves current settings to localStorage
 */
function saveSettings() {
    const settings = {
        length: elements.lengthSlider.value,
        uppercase: elements.uppercaseCheckbox.checked,
        lowercase: elements.lowercaseCheckbox.checked,
        numbers: elements.numbersCheckbox.checked,
        symbols: elements.symbolsCheckbox.checked,
        passwordHistory: state.passwordHistory
    };
    
    try {
        localStorage.setItem('passwordGeneratorSettings', JSON.stringify(settings));
    } catch (err) {
        console.warn('Could not save settings:', err);
    }
}

/**
 * Loads settings from localStorage
 */
function loadSettings() {
    try {
        const saved = localStorage.getItem('passwordGeneratorSettings');
        if (!saved) return false;
        
        const settings = JSON.parse(saved);
        
        // Restore values
        if (settings.length) {
            elements.lengthSlider.value = settings.length;
            elements.lengthValue.textContent = settings.length;
        }
        
        if (typeof settings.uppercase === 'boolean') {
            elements.uppercaseCheckbox.checked = settings.uppercase;
        }
        if (typeof settings.lowercase === 'boolean') {
            elements.lowercaseCheckbox.checked = settings.lowercase;
        }
        if (typeof settings.numbers === 'boolean') {
            elements.numbersCheckbox.checked = settings.numbers;
        }
        if (typeof settings.symbols === 'boolean') {
            elements.symbolsCheckbox.checked = settings.symbols;
        }
        
        if (settings.passwordHistory) {
            state.passwordHistory = settings.passwordHistory;
            renderHistory();
        }
        
        return true;
    } catch (err) {
        console.warn('Could not load settings:', err);
        return false;
    }
}

// ========================================
// Event Handlers
// ========================================

/**
 * Handles generate button click
 */
function handleGenerate() {
    const password = generatePassword();
    
    if (password) {
        elements.passwordDisplay.value = password;
        updateStrengthIndicator(password);
        addToHistory(password);
        saveSettings();
    }
}

/**
 * Handles regenerate button click
 */
function handleRegenerate() {
    handleGenerate();
}

/**
 * Handles length slider change
 */
function handleLengthChange() {
    const length = elements.lengthSlider.value;
    elements.lengthValue.textContent = length;
    
    // Auto-generate on slider change (Optional Enhancement)
    // Uncomment the next line to enable auto-generate
    // handleGenerate();
    
    saveSettings();
}

/**
 * Handles checkbox changes - clears error when user fixes options
 */
function handleCheckboxChange() {
    // Auto-clear error message when user fixes options (Requirement 9)
    clearError();
    saveSettings();
}

// ========================================
// Initialization
// ========================================

/**
 * Sets up all event listeners
 */
function setupEventListeners() {
    // Generate buttons
    elements.generateBtn.addEventListener('click', handleGenerate);
    elements.regenerateBtn.addEventListener('click', handleRegenerate);
    
    // Length slider
    elements.lengthSlider.addEventListener('input', handleLengthChange);
    elements.lengthSlider.addEventListener('change', handleLengthChange);
    
    // Checkboxes
    elements.uppercaseCheckbox.addEventListener('change', handleCheckboxChange);
    elements.lowercaseCheckbox.addEventListener('change', handleCheckboxChange);
    elements.numbersCheckbox.addEventListener('change', handleCheckboxChange);
    elements.symbolsCheckbox.addEventListener('change', handleCheckboxChange);
    
    // Copy button
    elements.copyBtn.addEventListener('click', copyPassword);
    
    // Toggle password visibility
    elements.togglePasswordBtn.addEventListener('click', togglePasswordVisibility);
    
    // Clear history
    elements.clearHistoryBtn.addEventListener('click', clearHistory);
    
    // Keyboard support for Enter key on password field
    elements.passwordDisplay.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            handleGenerate();
        }
    });
}

/**
 * Initializes the application
 */
function init() {
    // Load saved settings
    loadSettings();
    
    // Set up event listeners
    setupEventListeners();
    
    // Clear any initial error
    clearError();
    
    // Generate initial password if settings exist
    const hasSelectedOptions = getSelectedCharacterSets();
    const hasAnySelected = Object.values(hasSelectedOptions).some(val => val);
    
    if (hasAnySelected) {
        handleGenerate();
    }
    
    console.log('Secure Password Generator initialized');
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
