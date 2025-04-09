const express = require('express');
const db = require('../database/db');
const { hashPassword, verifyPassword } = require('../utils/cryptoUtils');
const { isValidEmail, isValidUsername, isValidPassword } = require('../utils/validationUtils');
const { createSessionCookie, clearSessionCookie } = require('../middleware/session');
const { requireGuest } = require('../middleware/auth'); // Use requireGuest for login/register pages

const router = express.Router();

// == Registration ==
router.get('/register', requireGuest, (req, res) => {
  res.render('auth/register', {
    title: 'Register',
    // user: req.user, // req.user will be null here due to requireGuest
    errors: {}, // Pass empty errors object initially
    formData: {}, // Pass empty form data initially
    // csrfToken: req.csrfToken, // Already available via res.locals
  });
});

router.post('/register', requireGuest, async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;
  const errors = {};
  const formData = { username, email }; // Don't retain passwords

  // Server-side Validation
  if (!isValidUsername(username)) errors.username = 'Username must be 3-20 characters, alphanumeric or underscores.';
  if (!isValidEmail(email)) errors.email = 'Please enter a valid email address.';
  if (!isValidPassword(password)) errors.password = 'Password must be at least 8 characters long.';
  if (password !== confirmPassword) errors.confirmPassword = 'Passwords do not match.';

  if (Object.keys(errors).length > 0) {
    return res.status(400).render('auth/register', {
      title: 'Register',
      // user: req.user,
      errors,
      formData,
      // csrfToken: req.csrfToken,
    });
  }

  try {
    // Check uniqueness (case-insensitive recommended)
    const existingUser = await db.get(
      'SELECT id, username, email FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)', // Select fields for specific error messages
      [username, email]
    );

    if (existingUser) {
      // Provide specific feedback if possible
      const lowerUsername = username.toLowerCase();
      const lowerEmail = email.toLowerCase();
      if (existingUser.username.toLowerCase() === lowerUsername) errors.username = 'Username already taken.';
      if (existingUser.email.toLowerCase() === lowerEmail) errors.email = 'Email already registered.';
      // Fallback generic error if needed
      if (Object.keys(errors).length === 0) errors.form = 'Username or email already exists.';


      return res.status(400).render('auth/register', {
        title: 'Register',
        // user: req.user,
        errors,
        formData,
        // csrfToken: req.csrfToken,
      });
    }

    // Hash password
    const { hash, salt } = hashPassword(password);

    // Insert user
    await db.run(
      'INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)',
      [username, email, hash, salt]
    );

    req.flash('success', 'Registration successful! Please log in.');
    res.redirect('/login');

  } catch (err) {
    console.error('Registration Error:', err);
    errors.form = 'An error occurred during registration. Please try again later.';
    res.status(500).render('auth/register', {
      title: 'Register',
      // user: req.user,
      errors,
      formData,
      // csrfToken: req.csrfToken,
    });
  }
});

// == Login ==
router.get('/login', requireGuest, (req, res) => {
  // Flash messages are automatically read from cookie/locals by middleware
  res.render('auth/login', {
    title: 'Login',
    // user: req.user,
    // error: req.flash('error'), // Handled by middleware setting res.locals
    // success: req.flash('success'), // Handled by middleware setting res.locals
    formData: {},
    // csrfToken: req.csrfToken,
  });
});

router.post('/login', requireGuest, async (req, res) => {
  const { identifier, password } = req.body; // Use 'identifier' for username or email
  const formData = { identifier }; // Retain identifier on error

  if (!identifier || !password) {
    req.flash('error', 'Please enter both username/email and password.');
    // Re-render with the message stored via flash
    return res.status(400).render('auth/login', {
        title: 'Login',
        // user: req.user,
        // error: req.flash('error'), // Read the message we just set
        // success: req.flash('success'),
        formData,
        // csrfToken: req.csrfToken,
    });
  }

  try {
    // Find user by username or email (case-insensitive)
    const user = await db.get(
      'SELECT id, username, password_hash, salt FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)',
      [identifier, identifier]
    );

    if (!user) {
      req.flash('error', 'Invalid username/email or password.');
      return res.status(401).render('auth/login', {
        title: 'Login',
        // user: req.user,
        // error: req.flash('error'),
        // success: req.flash('success'),
        formData,
        // csrfToken: req.csrfToken,
      });
    }

    // Verify password using timing-safe comparison
    const isMatch = verifyPassword(password, user.password_hash, user.salt);

    if (!isMatch) {
      req.flash('error', 'Invalid username/email or password.');
      return res.status(401).render('auth/login', {
        title: 'Login',
        // user: req.user,
        // error: req.flash('error'),
        // success: req.flash('success'),
        formData,
        // csrfToken: req.csrfToken,
      });
    }

    // Password is correct, create session
    createSessionCookie(res, { id: user.id, username: user.username });

    // Redirect to home page after successful login
    req.flash('success', `Welcome back, ${user.username}!`);
    res.redirect('/');

  } catch (err) {
    console.error('Login Error:', err);
    req.flash('error', 'An error occurred during login. Please try again later.');
     res.status(500).render('auth/login', {
        title: 'Login',
        // user: req.user,
        // error: req.flash('error'),
        // success: req.flash('success'),
        formData,
        // csrfToken: req.csrfToken,
    });
  }
});

// == Logout ==
router.post('/logout', (req, res) => {
    // CSRF protection is handled by the global middleware for POST
    clearSessionCookie(res);
    req.flash('success', 'You have been logged out.');
    res.redirect('/');
});


module.exports = router;
