/**
 * OWASP Juice Shop Login Form - Client-side Logic & Validation
 * CS 477 - Homework 2-B
 */

// DOM Elements
const loginForm = document.getElementById('loginForm');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const emailError = document.getElementById('emailError');
const passwordError = document.getElementById('passwordError');
const alertBox = document.getElementById('alertBox');
const togglePasswordBtn = document.getElementById('togglePassword');
const submitBtn = document.getElementById('submitBtn');
const btnText = document.getElementById('btnText');
const btnSpinner = document.getElementById('btnSpinner');

/**
 * Validates login input fields according to assignment requirements:
 * 1. Prevents empty submissions.
 * 2. Checks email contains "@".
 * 3. Checks password is at least 8 characters.
 *
 * @param {string} email
 * @param {string} password
 * @returns {{ isValid: boolean, errors: { email?: string, password?: string } }}
 */
function validateCredentials(email, password) {
  const errors = {};
  const trimmedEmail = (email || '').trim();

  // 1. Client-side empty validation
  if (!trimmedEmail) {
    errors.email = 'Please provide an email address.';
  } else if (!trimmedEmail.includes('@')) {
    // 2. Email must contain '@'
    errors.email = 'Email address must contain an "@" symbol (e.g. user@domain.com).';
  }

  // 1. Client-side empty validation for password
  if (!password) {
    errors.password = 'Please provide a password.';
  } else if (password.length < 8) {
    // 3. Password must be at least 8 characters
    errors.password = 'Password must be at least 8 characters long.';
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors
  };
}

/**
 * Renders validation errors to the DOM securely using textContent
 * to prevent DOM-based XSS attacks.
 */
function displayValidationErrors(errors) {
  // Clear previous field errors
  emailError.textContent = '';
  passwordError.textContent = '';
  emailInput.closest('.form-group').classList.remove('has-error');
  passwordInput.closest('.form-group').classList.remove('has-error');

  if (errors.email) {
    emailError.textContent = errors.email;
    emailInput.closest('.form-group').classList.add('has-error');
  }

  if (errors.password) {
    passwordError.textContent = errors.password;
    passwordInput.closest('.form-group').classList.add('has-error');
  }
}

/**
 * Displays status alert message securely using textContent.
 * @param {string} message
 * @param {'success' | 'error'} type
 */
function showAlert(message, type) {
  alertBox.className = `alert ${type}`;
  alertBox.textContent = message; // Safe sink: prevents XSS
  alertBox.classList.remove('hidden');
}

function clearAlert() {
  alertBox.className = 'alert hidden';
  alertBox.textContent = '';
}

// Toggle password visibility
togglePasswordBtn.addEventListener('click', () => {
  const currentType = passwordInput.getAttribute('type');
  if (currentType === 'password') {
    passwordInput.setAttribute('type', 'text');
    togglePasswordBtn.textContent = '🙈';
  } else {
    passwordInput.setAttribute('type', 'password');
    togglePasswordBtn.textContent = '👁️';
  }
});

// Clear field errors on input
emailInput.addEventListener('input', () => {
  if (emailError.textContent) {
    emailError.textContent = '';
    emailInput.closest('.form-group').classList.remove('has-error');
  }
});

passwordInput.addEventListener('input', () => {
  if (passwordError.textContent) {
    passwordError.textContent = '';
    passwordInput.closest('.form-group').classList.remove('has-error');
  }
});

// Form Submission Handler
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAlert();

  const email = emailInput.value;
  const password = passwordInput.value;

  // Step 1: Execute client-side validation
  const validation = validateCredentials(email, password);
  if (!validation.isValid) {
    displayValidationErrors(validation.errors);
    showAlert('Please resolve the errors highlighted below.', 'error');
    return;
  }

  // Clear any existing errors
  displayValidationErrors({});

  // Step 2: Send credentials to server for server-side validation & auth
  setLoading(true);

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (response.ok && data.success) {
      showAlert(`✅ ${data.message} Welcome back, ${data.user.email}!`, 'success');
    } else {
      // Server returned validation or authentication error
      if (data.errors && typeof data.errors === 'object') {
        displayValidationErrors(data.errors);
      }
      showAlert(`❌ ${data.message || 'Authentication failed.'}`, 'error');
    }
  } catch (err) {
    showAlert('❌ Network error: Could not reach the authentication server.', 'error');
  } finally {
    setLoading(false);
  }
});

function setLoading(isLoading) {
  submitBtn.disabled = isLoading;
  if (isLoading) {
    btnText.textContent = 'Verifying...';
    btnSpinner.classList.remove('hidden');
  } else {
    btnText.textContent = 'Log in';
    btnSpinner.classList.add('hidden');
  }
}
