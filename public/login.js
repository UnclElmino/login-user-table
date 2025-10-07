// public/login.js
const form = document.getElementById('loginForm');
const nameGroup = document.getElementById('nameGroup');
const formTitle = document.getElementById('formTitle');
const loginOptions = document.getElementById('loginOptions');
const submitBtn = document.getElementById('submitBtn');
const toggleText = document.getElementById('toggleText');
const toggleLink = document.getElementById('toggleLink');
const rememberMe = document.getElementById('rememberMe');
const forgotPassword = document.getElementById('forgotPassword');

let mode = 'login';

const alertBox = document.getElementById('formAlert');

// TOGGLE LOGIN <-> SIGNUP
toggleLink.addEventListener('click', (e) => {
  e.preventDefault();
  if (mode === 'login') {
    // Switch to sign-up
    mode = 'register';
    nameGroup.style.display = 'block';
    loginOptions.classList.add('d-none');
    loginOptions.classList.remove('d-flex');
    submitBtn.textContent = 'Sign Up';
    formTitle.textContent = 'Create Account';
    toggleText.textContent = 'Already have an account?';
    toggleLink.textContent = 'Login';
  } else {
    // Switch to login
    mode = 'login';
    nameGroup.style.display = 'none';
    loginOptions.classList.remove('d-none');
    loginOptions.classList.add('d-flex');
    submitBtn.textContent = 'Login';
    formTitle.textContent = 'Login';
    toggleText.textContent = 'Don’t have an account?';
    toggleLink.textContent = 'Sign up';
  }
});

// FORM SUBMIT HANDLER
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert();

  const email = form.email.value.trim();
  const password = form.password.value;
  const name = form.name?.value?.trim();

  submitBtn.disabled = true;
  submitBtn.innerText = (mode === 'register') ? 'Signing up…' : 'Signing in…';

  try {
    if (mode === 'register') {
      if (!name) {
        showAlert('warning', 'Please enter your full name.');
        return;
      } else {
        if (!email || !password) {
          showAlert('warning', 'Please enter both email and password.');
          return;
        }
      }
      const res = await fetch('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        showAlert('danger', body.error || 'Invalid email or password.');
        return;
      }
      showAlert('info', 'Registered! Check your email for the verification link.');
      // wait a few seconds
      setTimeout(() => {
        // switch UI back to login mode
        mode = 'login';
        nameGroup.style.display = 'none';
        loginOptions.classList.remove('d-none');
        loginOptions.classList.add('d-flex');
        submitBtn.textContent = 'Login';
        formTitle.textContent = 'Login';
        toggleText.textContent = 'Don’t have an account?';
        toggleLink.textContent = 'Sign up';
        hideAlert();
      }, 1000);

      return;
    }

    // LOGIN
    const r = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const body = await r.json().catch(() => ({}));

    if (!r.ok) {
      showAlert('danger', body.error || 'Invalid email or password.');
      // Optional: focus the password field
      document.getElementById('password').focus();
      return;
    }

    // store token (remember/session as you already do)
    if (rememberMe.checked) {
      localStorage.setItem('token', body.token);
    } else {
      sessionStorage.setItem('token', body.token);
    }
    location.href = '/table.html';
  } catch (err) {
    console.error(err);
    showAlert('danger', 'Network error. Please try again.');
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerText = (mode === 'register') ? 'Sign Up' : 'Login';
  }
});

function showAlert(type, msg) {
  // type: 'danger' | 'success' | 'warning' | 'info'
  alertBox.className = `alert alert-${type}`;
  alertBox.textContent = msg;
  alertBox.classList.remove('d-none');
}

function hideAlert() {
  alertBox.classList.add('d-none');
  alertBox.textContent = '';
}

const params = new URLSearchParams(location.search);
if (params.get('verified') === '1') {
  showAlert('success', 'Email verified! You can log in now.');
  history.replaceState({}, '', location.pathname); // clean URL
}

