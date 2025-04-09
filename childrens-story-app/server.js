const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const config = require('./src/config');
const db = require('./src/database/db');
const { sessionMiddleware } = require('./src/middleware/session');
const { csrfProtectionMiddleware } = require('./src/middleware/csrf');

// Import Routes
const indexRoutes = require('./src/routes/index');
const authRoutes = require('./src/routes/auth');
const storyRoutes = require('./src/routes/stories');

const app = express();

// Simple Flash Message Middleware (In-memory, basic)
app.use((req, res, next) => {
    // This basic implementation relies on routes passing messages directly to render
    // or storing them in res.locals before a redirect (which might not always work reliably without better storage).
    const flashMessages = req.cookies?.flash || {}; // Example using a temporary cookie (needs setting on redirect)
    res.locals.success = flashMessages.success || [];
    res.locals.error = flashMessages.error || [];
    res.clearCookie('flash'); // Clear flash cookie after reading

    req.flash = (type, message) => {
        if (message) {
            const currentFlash = req.cookies.flash || {};
            currentFlash[type] = currentFlash[type] || [];
            currentFlash[type].push(message);
            // Set cookie to pass flash messages across one redirect
            res.cookie('flash', currentFlash, { path: '/', maxAge: 60000 }); // Short expiry
        }
        // Return messages currently in locals for immediate rendering
        return res.locals[type] || [];
    };
    next();
});


// View Engine Setup
app.set('views', path.join(__dirname, 'src', 'views'));
app.set('view engine', 'ejs');

// Pass config to app instance for access in middleware/routes if needed
app.set('config', config);

// Middleware
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: false })); // Parse URL-encoded bodies
app.use(cookieParser(config.sessionSecret)); // Parse cookies, pass secret if signing/unsigning needed by parser itself (though we do custom signing)
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

// Custom Middleware Order is Important!
app.use(sessionMiddleware); // 1. Attach user session info (req.user) from signed cookie
app.use(csrfProtectionMiddleware); // 2. Handle CSRF token generation and validation

// Make user and flash messages available to all templates
app.use((req, res, next) => {
  res.locals.user = req.user; // From sessionMiddleware
  // Flash messages are read from cookie/locals by the flash middleware
  res.locals.csrfToken = req.csrfToken; // Ensure CSRF token is available globally for forms
  next();
});


// Routes
app.use('/', indexRoutes);
app.use('/', authRoutes);
app.use('/', storyRoutes); // Mount story routes (includes /api routes)


// Catch 404 and forward to error handler
app.use((req, res, next) => {
  res.status(404).render('errors/404', { title: 'Not Found', user: req.user });
});

// Generic Error Handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err.stack || err);

  // Set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = config.isProduction ? {} : err;

  // Render the error page
  res.status(err.status || 500);
  res.render('errors/500', { title: 'Server Error', user: req.user });
});

// Initialize Database Schema on startup (optional, can be done manually)
// Consider running `npm run db:init` manually for more control
db.initDb().catch(err => {
    console.error("Failed to initialize database on startup:", err);
    // Decide if you want to exit if DB init fails critically
    // process.exit(1);
});


// Start Server
app.listen(config.port, () => {
  console.log(`Server running in ${config.nodeEnv} mode on http://localhost:${config.port}`);
});
