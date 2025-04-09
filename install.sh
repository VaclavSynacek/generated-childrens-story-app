#!/bin/bash

# Stop on error
set -e

echo "Creating project structure..."

# Create directories
mkdir -p childrens-story-app/data
mkdir -p childrens-story-app/public/css
mkdir -p childrens-story-app/public/js
mkdir -p childrens-story-app/public/images
mkdir -p childrens-story-app/src/config
mkdir -p childrens-story-app/src/database
mkdir -p childrens-story-app/src/middleware
mkdir -p childrens-story-app/src/routes
mkdir -p childrens-story-app/src/services
mkdir -p childrens-story-app/src/utils
mkdir -p childrens-story-app/src/views/partials
mkdir -p childrens-story-app/src/views/auth
mkdir -p childrens-story-app/src/views/errors
mkdir -p childrens-story-app/src/views/story

echo "Creating project files..."

# --- Root Files ---

# .gitignore
cat << 'EOF' > childrens-story-app/.gitignore
node_modules/
.env
data/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
EOF
echo "Created .gitignore"

# jsconfig.json
cat << 'EOF' > childrens-story-app/jsconfig.json
{
  "compilerOptions": {
    "module": "CommonJS",
    "target": "ES2020",
    "checkJs": true
  },
  "include": ["src/**/*", "server.js"],
  "exclude": ["node_modules"]
}
EOF
echo "Created jsconfig.json"

# package.json
cat << 'EOF' > childrens-story-app/package.json
{
  "name": "childrens-story-app",
  "version": "1.0.0",
  "description": "Children's Story Application",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "concurrently \"npm run watch:css\" \"nodemon server.js\"",
    "build:css": "tailwindcss -i ./src/input.css -o ./public/css/styles.css --minify",
    "watch:css": "tailwindcss -i ./src/input.css -o ./public/css/styles.css --watch",
    "db:init": "node -e \"require('./src/database/db.js').initDb().catch(err => console.error('DB Init Error:', err))\""
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "cookie-parser": "^1.4.6",
    "dotenv": "^16.4.5",
    "ejs": "^3.1.9",
    "express": "^4.18.3",
    "sqlite3": "^5.1.7"
  },
  "devDependencies": {
    "autoprefixer": "^10.4.18",
    "concurrently": "^8.2.2",
    "nodemon": "^3.1.0",
    "postcss": "^8.4.35",
    "tailwindcss": "^3.4.1"
  }
}
EOF
echo "Created package.json"

# tailwind.config.js
cat << 'EOF' > childrens-story-app/tailwind.config.js
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/views/**/*.ejs',
    './public/js/**/*.js',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
EOF
echo "Created tailwind.config.js"

# postcss.config.js
cat << 'EOF' > childrens-story-app/postcss.config.js
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
EOF
echo "Created postcss.config.js"

# server.js
cat << 'EOF' > childrens-story-app/server.js
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
    const flashMessages = req.cookies.flash || {}; // Example using a temporary cookie (needs setting on redirect)
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
EOF
echo "Created server.js"

# --- src/config ---

# src/config/index.js
cat << 'EOF' > childrens-story-app/src/config/index.js
require('dotenv').config();

const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,
  databaseUrl: process.env.DATABASE_URL,
  sessionSecret: process.env.SESSION_SECRET,
  geminiApiKey: process.env.GEMINI_API_KEY,
  isProduction: process.env.NODE_ENV === 'production',
};

// Validate essential configuration
if (!config.databaseUrl) {
  console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
  process.exit(1);
}

if (!config.sessionSecret || config.sessionSecret.length < 32) {
  console.error(
    'FATAL ERROR: SESSION_SECRET environment variable is not set or is too short (must be at least 32 characters).'
  );
  process.exit(1);
}

if (!config.geminiApiKey && config.isProduction) {
    // Allow missing key in dev for basic testing without AI
    console.warn('WARNING: GEMINI_API_KEY environment variable is not set. Story generation will fail.');
} else if (!config.geminiApiKey && !config.isProduction) {
     console.warn('WARNING: GEMINI_API_KEY environment variable is not set. Story generation will fail.');
}


module.exports = config;
EOF
echo "Created src/config/index.js"

# --- src/database ---

# src/database/schema.sql
cat << 'EOF' > childrens-story-app/src/database/schema.sql
-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Stories Table
CREATE TABLE IF NOT EXISTS stories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    author_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    difficulty TEXT NOT NULL CHECK(difficulty IN ('Easy', 'Medium', 'Hard')),
    theme TEXT NOT NULL,
    characters TEXT NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_stories_author_id ON stories(author_id);
CREATE INDEX IF NOT EXISTS idx_stories_created_at ON stories(created_at);

-- Votes Table
CREATE TABLE IF NOT EXISTS votes (
    user_id INTEGER NOT NULL,
    story_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, story_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (story_id) REFERENCES stories(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_votes_story_id ON votes(story_id);

-- Enable foreign key support
PRAGMA foreign_keys = ON;
EOF
echo "Created src/database/schema.sql"

# src/database/db.js
cat << 'EOF' > childrens-story-app/src/database/db.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const config = require('../config');

const dbPath = config.databaseUrl.startsWith('file:')
  ? config.databaseUrl.substring(5)
  : config.databaseUrl;

// Ensure the directory exists
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
  console.log(`Created database directory: ${dbDir}`);
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
    process.exit(1); // Exit if DB connection fails
  } else {
    console.log(`Connected to the SQLite database at ${dbPath}`);
    // Enable foreign key constraints
    db.exec('PRAGMA foreign_keys = ON;', (execErr) => {
        if(execErr) {
            console.error("Error enabling foreign keys:", execErr.message);
        }
    });
  }
});

// Promise-based wrappers for common operations
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      // Use function() to access 'this' (lastID, changes)
      if (err) {
        console.error('DB Run Error:', err.message, 'SQL:', sql, 'Params:', params);
        reject(err);
      } else {
        resolve({ lastID: this.lastID, changes: this.changes });
      }
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        console.error('DB Get Error:', err.message, 'SQL:', sql, 'Params:', params);
        reject(err);
      } else {
        resolve(row);
      }
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        console.error('DB All Error:', err.message, 'SQL:', sql, 'Params:', params);
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
}

// Function to initialize the database schema
async function initDb() {
  try {
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    // Split schema into individual statements to execute sequentially
    const statements = schemaSql.split(';').filter(s => s.trim() !== '');

    console.log('Initializing database schema...');
    // Use serialize to ensure statements run in order
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.exec('BEGIN TRANSACTION;', (beginErr) => { // Wrap in transaction
                if (beginErr) return reject(beginErr);

                statements.forEach((statement, index) => {
                    if (statement.trim()) { // Ensure not empty
                        db.run(statement + ';', (err) => { // Add semicolon back
                            if (err) {
                                // Ignore "already exists" errors for tables/indexes
                                if (!err.message.includes('already exists')) {
                                    console.error(`Schema Error executing: ${statement}\n`, err.message);
                                    db.exec('ROLLBACK;', () => reject(err)); // Rollback on error
                                }
                            }
                            // Check if this is the last statement to commit/resolve
                            if (index === statements.length - 1) {
                                db.exec('COMMIT;', (commitErr) => {
                                    if (commitErr) {
                                        reject(commitErr);
                                    } else {
                                        console.log('Database schema initialization finished successfully.');
                                        resolve();
                                    }
                                });
                            }
                        });
                    } else if (index === statements.length - 1) {
                         // Handle case where last item is empty after split
                         db.exec('COMMIT;', (commitErr) => {
                            if (commitErr) {
                                reject(commitErr);
                            } else {
                                console.log('Database schema initialization finished successfully (last statement empty).');
                                resolve();
                            }
                        });
                    }
                });
            });
        });
    });

  } catch (err) {
    console.error('Failed to initialize database schema:', err);
    throw err; // Re-throw to indicate failure
  }
}

module.exports = {
  db, // Export the raw db instance if needed elsewhere
  run,
  get,
  all,
  initDb,
};
EOF
echo "Created src/database/db.js"

# --- src/middleware ---

# src/middleware/session.js
cat << 'EOF' > childrens-story-app/src/middleware/session.js
const config = require('../config');
const { signData, verifySignature } = require('../utils/cryptoUtils');

const SESSION_COOKIE_NAME = 'session';
// Optional: Add session expiration (e.g., 1 day)
const SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 1 day in milliseconds

/**
 * Custom session middleware using signed cookies.
 */
function sessionMiddleware(req, res, next) {
  req.user = null; // Default to no user
  const cookie = req.cookies[SESSION_COOKIE_NAME];

  if (!cookie) {
    return next();
  }

  const parts = cookie.split('.');
  if (parts.length !== 2) {
    console.warn('Invalid session cookie format received.');
    clearSessionCookie(res); // Clear malformed cookie
    return next();
  }

  const [encodedPayload, signature] = parts;
  let serializedPayload;
  try {
      serializedPayload = Buffer.from(encodedPayload, 'base64').toString('utf8');
  } catch (e) {
      console.warn('Invalid base64 encoding in session cookie payload.');
      clearSessionCookie(res);
      return next();
  }


  if (!verifySignature(serializedPayload, signature, config.sessionSecret)) {
    console.warn('Invalid session cookie signature.');
    clearSessionCookie(res); // Clear invalid cookie
    return next();
  }

  try {
    const payload = JSON.parse(serializedPayload);

    // Optional: Check expiration
    if (payload.exp && Date.now() > payload.exp) {
        console.log('Session cookie expired.');
        clearSessionCookie(res);
        return next();
    }

    // Session is valid, attach user info to request
    // Basic validation of payload content
    if (typeof payload.userId !== 'number' || typeof payload.username !== 'string') {
        console.warn('Invalid payload structure in session cookie.');
        clearSessionCookie(res);
        return next();
    }

    req.user = {
      id: payload.userId,
      username: payload.username,
    };
    // console.log(`Session validated for user: ${req.user.username} (ID: ${req.user.id})`);

  } catch (error) {
    console.error('Error parsing session payload:', error);
    clearSessionCookie(res); // Clear corrupted cookie
  }

  next();
}

/**
 * Creates and sets the session cookie on the response.
 * @param {import('express').Response} res The Express response object.
 * @param {{id: number, username: string}} userData User data to store.
 */
function createSessionCookie(res, userData) {
  const payload = {
    userId: userData.id,
    username: userData.username,
    iat: Date.now(),
    exp: Date.now() + SESSION_MAX_AGE_MS, // Add expiration timestamp
  };
  const serializedPayload = JSON.stringify(payload);
  const encodedPayload = Buffer.from(serializedPayload).toString('base64');
  const signature = signData(serializedPayload, config.sessionSecret);

  const cookieValue = `${encodedPayload}.${signature}`;

  res.cookie(SESSION_COOKIE_NAME, cookieValue, {
    httpOnly: true, // Prevent client-side JS access
    secure: config.isProduction, // Send only over HTTPS in production
    sameSite: 'Lax', // Recommended for most cases (CSRF protection)
    path: '/',
    maxAge: SESSION_MAX_AGE_MS, // Set cookie expiration
  });
   // console.log(`Session cookie created for user: ${userData.username}`);
}

/**
 * Clears the session cookie.
 * @param {import('express').Response} res The Express response object.
 */
function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: 'Lax',
    path: '/',
  });
  // console.log('Session cookie cleared.');
}

module.exports = {
  sessionMiddleware,
  createSessionCookie,
  clearSessionCookie,
};
EOF
echo "Created src/middleware/session.js"

# src/middleware/auth.js
cat << 'EOF' > childrens-story-app/src/middleware/auth.js
/**
 * Middleware to ensure the user is authenticated.
 * Redirects to login page if not authenticated.
 */
function requireAuth(req, res, next) {
  if (req.user && req.user.id) {
    // console.log('requireAuth: User authenticated, proceeding.');
    next();
  } else {
    // console.log('requireAuth: User not authenticated, redirecting to login.');
    req.flash('error', 'You must be logged in to view this page.');
    res.redirect('/login');
  }
}

 /**
 * Middleware to ensure the user is NOT authenticated (e.g., for login/register pages).
 * Redirects to home page if already logged in.
 */
function requireGuest(req, res, next) {
    if (!req.user) {
        next();
    } else {
        res.redirect('/');
    }
}


module.exports = { requireAuth, requireGuest };
EOF
echo "Created src/middleware/auth.js"

# src/middleware/csrf.js
cat << 'EOF' > childrens-story-app/src/middleware/csrf.js
const { generateCsrfToken } = require('../utils/cryptoUtils');

const CSRF_COOKIE_NAME = '_csrfToken';
const CSRF_HEADER_NAME = 'x-csrf-token'; // Or use form field name
const CSRF_FORM_FIELD = '_csrfToken';

/**
 * CSRF Protection Middleware (Double Submit Cookie Pattern)
 */
function csrfProtectionMiddleware(req, res, next) {
    let token = req.cookies[CSRF_COOKIE_NAME];

    // 1. Generate/Set Token Cookie if missing or on GET request
    if (!token) {
        token = generateCsrfToken();
        res.cookie(CSRF_COOKIE_NAME, token, {
            // Not HttpOnly: Client JS needs to read this for fetch headers
            secure: req.app.get('config').isProduction,
            sameSite: 'Lax',
            path: '/',
        });
        // console.log('CSRF: New token cookie set.');
    }
    // Make token available for forms and potentially JS (though reading from cookie is better for JS)
    req.csrfToken = token; // Attach to request object
    res.locals.csrfToken = token; // Make available to templates

    // 2. Verify Token on state-changing methods (POST, PUT, DELETE, etc.)
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        const tokenFromRequest =
            req.body[CSRF_FORM_FIELD] || // Check form body first
            req.headers[CSRF_HEADER_NAME.toLowerCase()]; // Then check header

        // console.log(`CSRF Check: Cookie='${token}', Request='${tokenFromRequest}'`);

        if (!tokenFromRequest || token !== tokenFromRequest) {
            console.warn('CSRF token mismatch or missing.');
            // Render a specific 403 page
            res.status(403).render('errors/403', {
                title: 'Forbidden',
                message: 'Invalid security token. Please refresh the page or form and try again.',
                user: req.user // Pass user for layout consistency
            });
            return;
        }
        // console.log('CSRF: Token verified for state-changing request.');
    }

    // Proceed for GET or if token verified
    next();
}

module.exports = { csrfProtectionMiddleware };
EOF
echo "Created src/middleware/csrf.js"

# --- src/services ---

# src/services/gemini.js
cat << 'EOF' > childrens-story-app/src/services/gemini.js
const https = require('https');
const config = require('../config');

const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${config.geminiApiKey}`;

/**
 * Generates a story using the Gemini API.
 * @param {string} theme
 * @param {string} characters
 * @param {'Easy' | 'Medium' | 'Hard'} difficulty
 * @returns {Promise<string>} The generated story content.
 * @throws {Error} If API call fails or returns an error.
 */
async function generateStory(theme, characters, difficulty) {
  if (!config.geminiApiKey) {
      console.error('Gemini API Key is missing. Cannot generate story.');
      throw new Error('Story generation service is not configured.');
  }

  const prompt = `Write a short children's story suitable for a reading difficulty level of '${difficulty}'. The story should be about the theme: '${theme}'. It should feature the following characters: '${characters}'. Keep the story engaging and appropriate for children. Do not include a title in the story output itself.`;

  const requestBody = JSON.stringify({
    contents: [
      {
        parts: [{ text: prompt }],
      },
    ],
    // Optional: Add safety settings, generation config if needed
    // "safetySettings": [ ... ],
    // "generationConfig": { "temperature": 0.7, ... }
  });

  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(requestBody),
    },
    timeout: 30000, // 30 second timeout
  };

  console.log(`Sending request to Gemini API... Theme: ${theme}`);

  return new Promise((resolve, reject) => {
    const req = https.request(GEMINI_API_URL, options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        console.log(`Gemini API Response Status: ${res.statusCode}`);
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            const responseBody = JSON.parse(data);
            // Navigate the Gemini response structure
            const text = responseBody?.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) {
              console.log('Gemini API Response Success.');
              resolve(text.trim());
            } else {
              console.error('Gemini API Error: Could not extract text from response:', JSON.stringify(responseBody, null, 2));
              reject(new Error('Failed to generate story: Invalid response structure from AI service.'));
            }
          } else {
             console.error(`Gemini API Error: Status ${res.statusCode}, Body: ${data}`);
             let errorMessage = `Failed to generate story: AI service returned status ${res.statusCode}.`;
             try { // Try to parse error details from Gemini
                const errorBody = JSON.parse(data);
                if (errorBody.error && errorBody.error.message) {
                    errorMessage += ` Details: ${errorBody.error.message}`;
                }
             } catch (parseError) { /* Ignore if error body isn't JSON */ }
             reject(new Error(errorMessage));
          }
        } catch (parseError) {
          console.error('Gemini API Error: Failed to parse response JSON:', parseError, 'Raw Data:', data);
          reject(new Error('Failed to generate story: Could not understand response from AI service.'));
        }
      });
    });

    req.on('error', (error) => {
      console.error('Gemini API Error: Network or request error:', error);
      reject(new Error(`Failed to generate story: Could not connect to AI service. ${error.message}`));
    });

    req.on('timeout', () => {
        console.error('Gemini API Error: Request timed out.');
        req.destroy(); // Destroy the request explicitly on timeout
        reject(new Error('Failed to generate story: The AI service took too long to respond.'));
    });


    req.write(requestBody);
    req.end();
  });
}

module.exports = { generateStory };
EOF
echo "Created src/services/gemini.js"

# --- src/utils ---

# src/utils/cryptoUtils.js
cat << 'EOF' > childrens-story-app/src/utils/cryptoUtils.js
const crypto = require('crypto');
const config = require('../config');

const HASH_ALGORITHM = 'sha512'; // Or 'sha256'
const HASH_ITERATIONS = 10000; // PBKDF2 iterations
const HASH_KEYLEN = 64; // PBKDF2 key length
const SALT_BYTES = 16;
const SIGNATURE_ALGORITHM = 'sha256';

/**
 * Hashes a password using PBKDF2.
 * @param {string} password The password to hash.
 * @returns {{ hash: string, salt: string }} The hex-encoded hash and salt.
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_BYTES).toString('hex');
  const hash = crypto
    .pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_KEYLEN, HASH_ALGORITHM)
    .toString('hex');
  return { salt, hash };
}

/**
 * Verifies a password against a stored hash and salt using PBKDF2.
 * Uses timing-safe comparison.
 * @param {string} providedPassword The password attempt.
 * @param {string} storedHash The hex-encoded hash from the database.
 * @param {string} salt The hex-encoded salt from the database.
 * @returns {boolean} True if the password matches, false otherwise.
 */
function verifyPassword(providedPassword, storedHash, salt) {
  try {
    const hashToCompare = crypto
      .pbkdf2Sync(providedPassword, salt, HASH_ITERATIONS, HASH_KEYLEN, HASH_ALGORITHM)
      .toString('hex');

    const storedHashBuffer = Buffer.from(storedHash, 'hex');
    const hashToCompareBuffer = Buffer.from(hashToCompare, 'hex');

    // Ensure buffers have the same length for timingSafeEqual
    if (storedHashBuffer.length !== hashToCompareBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(storedHashBuffer, hashToCompareBuffer);
  } catch (error) {
    console.error('Error verifying password:', error);
    return false; // Treat errors as verification failure
  }
}

/**
 * Signs data using HMAC-SHA256.
 * @param {string} data The data to sign (usually stringified JSON).
 * @param {string} secret The secret key.
 * @returns {string} The hex-encoded signature.
 */
function signData(data, secret) {
  return crypto
    .createHmac(SIGNATURE_ALGORITHM, secret)
    .update(data)
    .digest('hex');
}

/**
 * Verifies an HMAC-SHA256 signature. Uses timing-safe comparison.
 * @param {string} data The data that was signed.
 * @param {string} signature The hex-encoded signature to verify.
 * @param {string} secret The secret key used for signing.
 * @returns {boolean} True if the signature is valid, false otherwise.
 */
function verifySignature(data, signature, secret) {
  try {
    const expectedSignature = signData(data, secret);

    const signatureBuffer = Buffer.from(signature, 'hex');
    const expectedSignatureBuffer = Buffer.from(expectedSignature, 'hex');

    if (signatureBuffer.length !== expectedSignatureBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(signatureBuffer, expectedSignatureBuffer);
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false; // Treat errors as verification failure
  }
}

/**
 * Generates a cryptographically secure random token (e.g., for CSRF).
 * @param {number} [bytes=32] Number of bytes for the token.
 * @returns {string} A hex-encoded random token.
 */
function generateCsrfToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

module.exports = {
  hashPassword,
  verifyPassword,
  signData,
  verifySignature,
  generateCsrfToken,
};
EOF
echo "Created src/utils/cryptoUtils.js"

# src/utils/validationUtils.js
cat << 'EOF' > childrens-story-app/src/utils/validationUtils.js
// Basic email regex (adjust for stricter validation if needed)
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Username: alphanumeric and underscores, 3-20 chars
const USERNAME_REGEX = /^[a-zA-Z0-9_]{3,20}$/;

function isValidEmail(email) {
  return typeof email === 'string' && EMAIL_REGEX.test(email);
}

function isValidUsername(username) {
  return typeof username === 'string' && USERNAME_REGEX.test(username);
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8;
}

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
}

function isValidDifficulty(difficulty) {
    return ['Easy', 'Medium', 'Hard'].includes(difficulty);
}

module.exports = {
  isValidEmail,
  isValidUsername,
  isValidPassword,
  isNonEmptyString,
  isValidDifficulty,
};
EOF
echo "Created src/utils/validationUtils.js"

# --- src/routes ---

# src/routes/auth.js
cat << 'EOF' > childrens-story-app/src/routes/auth.js
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
EOF
echo "Created src/routes/auth.js"

# src/routes/index.js
cat << 'EOF' > childrens-story-app/src/routes/index.js
const express = require('express');
const db = require('../database/db');

const router = express.Router();

// UC-1 & UC-5: Index Page (Browse Stories)
router.get('/', async (req, res) => {
  try {
    const userId = req.user ? req.user.id : null;

    // Optimized query to get stories, author usernames, vote counts, and user's vote status
    const sql = `
        SELECT
            s.id,
            s.title,
            s.content,
            s.difficulty,
            u.username AS author_username,
            COUNT(v.story_id) AS vote_count
            ${userId ? ', MAX(CASE WHEN v_user.user_id IS NOT NULL THEN 1 ELSE 0 END) AS user_voted' : ''}
        FROM stories s
        LEFT JOIN users u ON s.author_id = u.id
        LEFT JOIN votes v ON s.id = v.story_id
        ${userId ? `LEFT JOIN votes v_user ON s.id = v_user.story_id AND v_user.user_id = ?` : ''}
        GROUP BY s.id, s.title, s.content, s.difficulty, u.username
        ORDER BY vote_count DESC, s.created_at DESC;
    `;

    const params = userId ? [userId] : [];
    const stories = await db.all(sql, params);

    // Truncate content for display
    const storiesForView = stories.map(story => ({
      ...story,
      excerpt: story.content.substring(0, 100) + (story.content.length > 100 ? '...' : ''),
    }));

    res.render('index', {
      title: 'Stories',
      // user: req.user, // Available via res.locals
      stories: storiesForView,
      // success: req.flash('success'), // Available via res.locals
      // error: req.flash('error'), // Available via res.locals
    });
  } catch (err) {
    console.error('Error fetching stories for index:', err);
    res.status(500).render('errors/500', { title: 'Server Error' /* user: req.user */ });
  }
});

// UC-2 & UC-6: Story Detail Page
router.get('/story/:id', async (req, res) => {
  const storyId = parseInt(req.params.id, 10);
  if (isNaN(storyId)) {
    return res.status(404).render('errors/404', { title: 'Not Found' /* user: req.user */ });
  }

  try {
    const userId = req.user ? req.user.id : null;

    // Fetch story details and author
    const storySql = `
        SELECT s.*, u.username AS author_username
        FROM stories s
        LEFT JOIN users u ON s.author_id = u.id
        WHERE s.id = ?;
    `;
    const story = await db.get(storySql, [storyId]);

    if (!story) {
      return res.status(404).render('errors/404', { title: 'Story Not Found' /* user: req.user */ });
    }

    // Fetch vote count
    const voteCountSql = 'SELECT COUNT(*) as count FROM votes WHERE story_id = ?';
    const voteResult = await db.get(voteCountSql, [storyId]);
    const voteCount = voteResult ? voteResult.count : 0;

    // Check if current user has voted (if logged in)
    let userVoted = false;
    if (userId) {
      const userVoteSql = 'SELECT 1 FROM votes WHERE user_id = ? AND story_id = ? LIMIT 1';
      const userVoteResult = await db.get(userVoteSql, [userId, storyId]);
      userVoted = !!userVoteResult; // Convert result to boolean
    }

    res.render('story/detail', {
      title: story.title,
      // user: req.user, // Available via res.locals
      story,
      voteCount,
      userVoted,
      // csrfToken: req.csrfToken, // Available via res.locals
    });

  } catch (err) {
    console.error(`Error fetching story detail (ID: ${storyId}):`, err);
    res.status(500).render('errors/500', { title: 'Server Error' /* user: req.user */ });
  }
});

module.exports = router;
EOF
echo "Created src/routes/index.js"

# src/routes/stories.js
cat << 'EOF' > childrens-story-app/src/routes/stories.js
const express = require('express');
const db = require('../database/db');
const { requireAuth } = require('../middleware/auth');
const { generateStory } = require('../services/gemini');
const { isNonEmptyString, isValidDifficulty } = require('../utils/validationUtils');

const router = express.Router();

// In-memory storage for wizard state (simple approach, lost on restart)
// Key: userId, Value: { theme, characters, difficulty, content, counter }
const wizardSessions = new Map();
const MAX_REGENERATIONS = 3; // Total attempts allowed (1 initial + 2 regenerations)

// --- Story Creation Wizard ---

// UC-7a: Step 1 - Define Details (GET)
router.get('/create-story/start', requireAuth, (req, res) => {
  // Clear any previous session data for this user
  wizardSessions.delete(req.user.id);
  res.render('story/create-step1', {
    title: 'Create Story - Step 1',
    // user: req.user, // Available via res.locals
    errors: {},
    formData: {},
    // csrfToken: req.csrfToken, // Available via res.locals
  });
});

// UC-7a & 7b: Step 1 - Define Details (POST) -> Generate -> Redirect to Review
router.post('/create-story/generate', requireAuth, async (req, res) => {
  const { theme, characters, difficulty } = req.body;
  const userId = req.user.id;
  const errors = {};
  const formData = { theme, characters, difficulty };

  // Validation
  if (!isNonEmptyString(theme)) errors.theme = 'Theme cannot be empty.';
  if (!isNonEmptyString(characters)) errors.characters = 'Characters cannot be empty.';
  if (!isValidDifficulty(difficulty)) errors.difficulty = 'Please select a valid difficulty.';

  if (Object.keys(errors).length > 0) {
    return res.status(400).render('story/create-step1', {
      title: 'Create Story - Step 1',
      // user: req.user,
      errors,
      formData,
      // csrfToken: req.csrfToken,
    });
  }

  // Store initial data in temporary session
  wizardSessions.set(userId, { theme, characters, difficulty, counter: 0, content: null });

  try {
    // UC-7b: Generate Story via Gemini
    console.log(`User ${userId} starting story generation...`);
    const currentSession = wizardSessions.get(userId);
    const generatedContent = await generateStory(theme, characters, difficulty);

    // Store generated content and increment counter
    currentSession.content = generatedContent;
    currentSession.counter = 1; // First attempt
    wizardSessions.set(userId, currentSession);
    console.log(`User ${userId} story generation attempt 1 successful.`);

    // Redirect to review step
    res.redirect('/create-story/review');

  } catch (err) {
    console.error(`Error during initial story generation for user ${userId}:`, err);
    wizardSessions.delete(userId); // Clean up session on error
    req.flash('error', `Story generation failed: ${err.message}`);
    // Redirect back to step 1 with error
    res.redirect('/create-story/start');
  }
});

// UC-7c: Step 3 - Review and Approve/Regenerate (GET)
router.get('/create-story/review', requireAuth, (req, res) => {
  const userId = req.user.id;
  const sessionData = wizardSessions.get(userId);

  if (!sessionData || !sessionData.content) {
    // If user lands here without going through steps, redirect to start
    req.flash('error', 'Please start the story creation process first.');
    return res.redirect('/create-story/start');
  }

  res.render('story/create-review', {
    title: 'Create Story - Review',
    // user: req.user, // Available via res.locals
    storyContent: sessionData.content,
    attempt: sessionData.counter,
    maxAttempts: MAX_REGENERATIONS,
    canRegenerate: sessionData.counter < MAX_REGENERATIONS,
    // csrfToken: req.csrfToken, // Available via res.locals
    // error: req.flash('error'), // Available via res.locals
  });
});

// UC-7c: Regenerate Story (POST) -> Generate -> Redirect back to Review
router.post('/create-story/regenerate', requireAuth, async (req, res) => {
    const userId = req.user.id;
    const sessionData = wizardSessions.get(userId);

    if (!sessionData) {
        req.flash('error', 'Session expired or invalid. Please start over.');
        return res.redirect('/create-story/start');
    }

    if (sessionData.counter >= MAX_REGENERATIONS) {
        req.flash('error', 'Maximum regeneration attempts reached.');
        return res.redirect('/create-story/review');
    }

    try {
        console.log(`User ${userId} regenerating story (Attempt ${sessionData.counter + 1})...`);
        // Use original theme, characters, difficulty
        const generatedContent = await generateStory(
            sessionData.theme,
            sessionData.characters,
            sessionData.difficulty
        );

        // Update session
        sessionData.content = generatedContent;
        sessionData.counter += 1;
        wizardSessions.set(userId, sessionData);
        console.log(`User ${userId} story regeneration attempt ${sessionData.counter} successful.`);

        res.redirect('/create-story/review');

    } catch (err) {
        console.error(`Error during story regeneration for user ${userId}:`, err);
        // Don't delete session here, allow user to see the previous version
        req.flash('error', `Story regeneration failed: ${err.message}`);
        res.redirect('/create-story/review');
    }
});


// UC-7d: Save Approved Story (POST from Review page)
router.post('/api/stories/create', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const sessionData = wizardSessions.get(userId);

  if (!sessionData || !sessionData.content) {
    // Should not happen if form submitted correctly, but handle defensively
    console.error(`Attempt to save story without session data for user ${userId}`);
    req.flash('error', 'Could not find story data to save. Please try creating again.');
    return res.redirect('/create-story/start');
  }

  try {
    // Generate a simple title (e.g., first few words)
    const title = sessionData.content.split(' ').slice(0, 10).join(' ').replace(/[.,!?;:]$/, '') + '...';

    // Save to database
    await db.run(
      `INSERT INTO stories (title, content, author_id, difficulty, theme, characters)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        title,
        sessionData.content,
        userId,
        sessionData.difficulty,
        sessionData.theme,
        sessionData.characters,
      ]
    );

    // Clear temporary session data
    wizardSessions.delete(userId);
    console.log(`Story created successfully by user ${userId}.`);

    req.flash('success', 'Story created successfully!');
    res.redirect('/');

  } catch (err) {
    console.error(`Error saving story for user ${userId}:`, err);
    req.flash('error', 'Failed to save the story to the database. Please try again.');
    // Redirect back to review page so user doesn't lose the content
    res.redirect('/create-story/review');
  }
});


// --- Story Voting ---

// UC-6a: Vote on Story (API Endpoint)
router.post('/api/stories/:id/vote', requireAuth, async (req, res) => {
  const storyId = parseInt(req.params.id, 10);
  const userId = req.user.id;

  if (isNaN(storyId)) {
    return res.status(400).json({ success: false, message: 'Invalid story ID.' });
  }

  try {
    // Attempt to insert the vote.
    // The PRIMARY KEY constraint (user_id, story_id) prevents duplicates.
    await db.run(
      'INSERT INTO votes (user_id, story_id) VALUES (?, ?)',
      [userId, storyId]
    );
    console.log(`User ${userId} voted successfully for story ${storyId}.`);
    res.status(201).json({ success: true, message: 'Vote recorded.' }); // 201 Created

  } catch (err) {
    // Check if the error is due to the unique constraint violation (already voted)
    if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('UNIQUE constraint failed: votes.user_id, votes.story_id')) {
        console.log(`User ${userId} attempted to vote again for story ${storyId}.`);
        // Treat as success from user perspective - idempotent
        res.status(200).json({ success: true, message: 'Already voted.' });
    } else if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('FOREIGN KEY constraint failed')) {
        console.error(`Vote Error: Story ID ${storyId} likely does not exist.`);
         res.status(404).json({ success: false, message: 'Story not found.' });
    }
    else {
      // Other database error
      console.error(`Error recording vote for story ${storyId} by user ${userId}:`, err);
      res.status(500).json({ success: false, message: 'Failed to record vote due to a server error.' });
    }
  }
});


module.exports = router;
EOF
echo "Created src/routes/stories.js"

# --- src/views ---

# src/views/layout.ejs
cat << 'EOF' > childrens-story-app/src/views/layout.ejs
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= title %> - Story App</title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body class="bg-gray-100 font-sans flex flex-col min-h-screen">
    <%- include('partials/header') %>

    <main class="container mx-auto px-4 py-8 flex-grow">
        <%- include('partials/messages') %>
        <%- body %>
    </main>

    <%- include('partials/footer') %>

    <!-- Include client-side JS -->
    <script src="/js/main.js"></script>
    <!-- Include specific page JS if needed, e.g., vote.js -->
</body>
</html>
EOF
echo "Created src/views/layout.ejs"

# src/views/partials/header.ejs
cat << 'EOF' > childrens-story-app/src/views/partials/header.ejs
<header class="bg-blue-600 text-white p-4 shadow-md">
    <nav class="container mx-auto flex justify-between items-center">
        <a href="/" class="text-2xl font-bold hover:text-blue-200">Story Time</a>
        <div>
            <% if (user) { %>
                <span class="mr-4">Welcome, <%= user.username %>!</span>
                <a href="/create-story/start" class="bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded mr-2 inline-block">Create Story</a>
                <!-- Logout needs to be a POST request, best handled by a small form -->
                <form action="/logout" method="POST" class="inline">
                     <!-- IMPORTANT: Include CSRF token for POST -->
                     <input type="hidden" name="_csrfToken" value="<%= typeof csrfToken !== 'undefined' ? csrfToken : '' %>">
                     <button type="submit" class="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded">Logout</button>
                </form>
            <% } else { %>
                <a href="/register" class="hover:text-blue-200 mr-4">Register</a>
                <a href="/login" class="bg-white text-blue-600 hover:bg-gray-200 font-bold py-2 px-4 rounded">Login</a>
            <% } %>
        </div>
    </nav>
</header>
EOF
echo "Created src/views/partials/header.ejs"

# src/views/partials/footer.ejs
cat << 'EOF' > childrens-story-app/src/views/partials/footer.ejs
<footer class="bg-gray-700 text-white text-center p-4 mt-8">
    <p>© <%= new Date().getFullYear() %> Children's Story App. All rights reserved.</p>
</footer>
EOF
echo "Created src/views/partials/footer.ejs"

# src/views/partials/messages.ejs
cat << 'EOF' > childrens-story-app/src/views/partials/messages.ejs
<% if (typeof success !== 'undefined' && success && success.length > 0) { %>
    <% success.forEach(msg => { %>
        <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative mb-4" role="alert">
            <strong class="font-bold">Success!</strong>
            <span class="block sm:inline"><%= msg %></span>
             <button type="button" class="absolute top-0 bottom-0 right-0 px-4 py-3" onclick="this.parentElement.remove();">
                <span class="text-green-500 hover:text-green-700 text-2xl" aria-hidden="true">×</span>
            </button>
        </div>
    <% }) %>
<% } %>
<% if (typeof error !== 'undefined' && error && error.length > 0) { %>
     <% error.forEach(msg => { %>
         <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
            <strong class="font-bold">Error!</strong>
            <span class="block sm:inline"><%= msg %></span>
             <button type="button" class="absolute top-0 bottom-0 right-0 px-4 py-3" onclick="this.parentElement.remove();">
                <span class="text-red-500 hover:text-red-700 text-2xl" aria-hidden="true">×</span>
            </button>
        </div>
     <% }) %>
<% } %>
<!-- Display form-specific errors if passed (e.g., from failed validation render) -->
 <% if (typeof errors !== 'undefined' && errors.form) { %>
     <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
        <strong class="font-bold">Error!</strong>
        <span class="block sm:inline"><%= errors.form %></span>
         <button type="button" class="absolute top-0 bottom-0 right-0 px-4 py-3" onclick="this.parentElement.remove();">
            <span class="text-red-500 hover:text-red-700 text-2xl" aria-hidden="true">×</span>
        </button>
    </div>
<% } %>
EOF
echo "Created src/views/partials/messages.ejs"

# src/views/index.ejs
cat << 'EOF' > childrens-story-app/src/views/index.ejs
<h1 class="text-3xl font-bold mb-6 text-gray-800">Available Stories</h1>
<% if (stories.length === 0) { %>
    <p class="text-gray-600">No stories available yet. Be the first to <a href="/create-story/start" class="text-blue-600 hover:underline">create one</a>!</p>
<% } else { %>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <% stories.forEach(story => { %>
            <div class="bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-shadow duration-200 flex flex-col justify-between">
                <div>
                    <h2 class="text-xl font-semibold mb-2">
                        <a href="/story/<%= story.id %>" class="text-blue-600 hover:underline"><%= story.title %></a>
                    </h2>
                    <p class="text-gray-600 text-sm mb-1">By: <%= story.author_username || 'Unknown Author' %></p>
                    <p class="text-gray-600 text-sm mb-3">Difficulty: <%= story.difficulty %></p>
                    <p class="text-gray-700 mb-4 text-sm"><%= story.excerpt %></p>
                </div>
                <div class="flex justify-between items-center mt-4 border-t pt-3">
                    <span class="text-gray-800 font-medium text-sm">Votes: <span id="vote-count-<%= story.id %>"><%= story.vote_count %></span></span>
                    <% if (user) { %>
                        <!-- Vote button handled by client-side JS -->
                        <button
                            class="vote-button <%= story.user_voted ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600' %> text-white font-bold py-1 px-3 rounded text-sm transition-colors duration-200"
                            data-story-id="<%= story.id %>"
                            <%= story.user_voted ? 'disabled' : '' %>
                            id="vote-btn-<%= story.id %>">
                            <%= story.user_voted ? 'Voted' : 'Vote Up' %>
                        </button>
                    <% } %>
                </div>
            </div>
        <% }); %>
    </div>
<% } %>
<!-- Include vote.js specifically for pages with vote buttons -->
<script src="/js/vote.js"></script>
EOF
echo "Created src/views/index.ejs"

# src/views/auth/login.ejs
cat << 'EOF' > childrens-story-app/src/views/auth/login.ejs
<div class="max-w-md mx-auto bg-white p-8 rounded-lg shadow-md mt-10">
    <h1 class="text-2xl font-bold mb-6 text-center">Login</h1>

    <form action="/login" method="POST" id="login-form">
        <!-- IMPORTANT: CSRF Token -->
        <input type="hidden" name="_csrfToken" value="<%= csrfToken %>">

        <div class="mb-4">
            <label for="identifier" class="block text-gray-700 text-sm font-bold mb-2">Username or Email:</label>
            <input type="text" id="identifier" name="identifier" required
                   class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.form ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                   value="<%= typeof formData !== 'undefined' && formData.identifier ? formData.identifier : '' %>">
        </div>

        <div class="mb-6">
            <label for="password" class="block text-gray-700 text-sm font-bold mb-2">Password:</label>
            <input type="password" id="password" name="password" required
                   class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.form ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline">
             <!-- General form error shown by messages partial -->
        </div>

        <div class="flex items-center justify-between">
            <button type="submit" class="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                Sign In
            </button>
            <a class="inline-block align-baseline font-bold text-sm text-blue-500 hover:text-blue-800" href="/register">
                Need an account? Register
            </a>
        </div>
    </form>
</div>
EOF
echo "Created src/views/auth/login.ejs"

# src/views/auth/register.ejs
cat << 'EOF' > childrens-story-app/src/views/auth/register.ejs
<div class="max-w-md mx-auto bg-white p-8 rounded-lg shadow-md mt-10">
    <h1 class="text-2xl font-bold mb-6 text-center">Register</h1>

    <form action="/register" method="POST" id="register-form">
         <!-- IMPORTANT: CSRF Token -->
        <input type="hidden" name="_csrfToken" value="<%= csrfToken %>">

        <div class="mb-4">
            <label for="username" class="block text-gray-700 text-sm font-bold mb-2">Username:</label>
            <input type="text" id="username" name="username" required minlength="3" maxlength="20" pattern="^[a-zA-Z0-9_]{3,20}$"
                   title="Username must be 3-20 characters, alphanumeric or underscores."
                   class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.username ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                   value="<%= typeof formData !== 'undefined' && formData.username ? formData.username : '' %>">
            <% if (typeof errors !== 'undefined' && errors.username) { %>
                <p class="text-red-500 text-xs italic mt-1"><%= errors.username %></p>
            <% } %>
        </div>

         <div class="mb-4">
            <label for="email" class="block text-gray-700 text-sm font-bold mb-2">Email Address:</label>
            <input type="email" id="email" name="email" required
                   class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.email ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                   value="<%= typeof formData !== 'undefined' && formData.email ? formData.email : '' %>">
             <% if (typeof errors !== 'undefined' && errors.email) { %>
                <p class="text-red-500 text-xs italic mt-1"><%= errors.email %></p>
            <% } %>
        </div>

        <div class="mb-4">
            <label for="password" class="block text-gray-700 text-sm font-bold mb-2">Password:</label>
            <input type="password" id="password" name="password" required minlength="8"
                   title="Password must be at least 8 characters long."
                   class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.password ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
             <% if (typeof errors !== 'undefined' && errors.password) { %>
                <p class="text-red-500 text-xs italic mt-1"><%= errors.password %></p>
            <% } %>
        </div>

         <div class="mb-6">
            <label for="confirmPassword" class="block text-gray-700 text-sm font-bold mb-2">Confirm Password:</label>
            <input type="password" id="confirmPassword" name="confirmPassword" required minlength="8"
                   class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.confirmPassword ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline">
             <p id="confirmPasswordError" class="text-red-500 text-xs italic mt-1">
                 <% if (typeof errors !== 'undefined' && errors.confirmPassword) { %><%= errors.confirmPassword %><% } %>
             </p>
        </div>

        <div class="flex items-center justify-between">
            <button type="submit" class="bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                Register
            </button>
             <a class="inline-block align-baseline font-bold text-sm text-blue-500 hover:text-blue-800" href="/login">
                Already have an account? Login
            </a>
        </div>
    </form>
</div>
EOF
echo "Created src/views/auth/register.ejs"

# src/views/errors/403.ejs
cat << 'EOF' > childrens-story-app/src/views/errors/403.ejs
<div class="text-center mt-10">
    <h1 class="text-6xl font-bold text-red-600">403</h1>
    <h2 class="text-3xl font-semibold text-gray-800 mt-4">Forbidden</h2>
    <p class="text-gray-600 mt-2"><%= typeof message !== 'undefined' ? message : 'You do not have permission to access this resource or your security token was invalid.' %></p>
    <a href="/" class="mt-6 inline-block bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded">
        Go Home
    </a>
</div>
EOF
echo "Created src/views/errors/403.ejs"

# src/views/errors/404.ejs
cat << 'EOF' > childrens-story-app/src/views/errors/404.ejs
<div class="text-center mt-10">
    <h1 class="text-6xl font-bold text-blue-600">404</h1>
    <h2 class="text-3xl font-semibold text-gray-800 mt-4">Page Not Found</h2>
    <p class="text-gray-600 mt-2">Sorry, the page you are looking for does not exist.</p>
    <a href="/" class="mt-6 inline-block bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded">
        Go Home
    </a>
</div>
EOF
echo "Created src/views/errors/404.ejs"

# src/views/errors/500.ejs
cat << 'EOF' > childrens-story-app/src/views/errors/500.ejs
<div class="text-center mt-10">
    <h1 class="text-6xl font-bold text-red-600">500</h1>
    <h2 class="text-3xl font-semibold text-gray-800 mt-4">Server Error</h2>
    <p class="text-gray-600 mt-2">Sorry, something went wrong on our end. Please try again later.</p>

    <% if (typeof error !== 'undefined' && process.env.NODE_ENV !== 'production') { %>
        <pre class="mt-4 p-4 bg-gray-200 text-left text-sm overflow-auto rounded"><%= error.stack %></pre>
    <% } %>

    <a href="/" class="mt-6 inline-block bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded">
        Go Home
    </a>
</div>
EOF
echo "Created src/views/errors/500.ejs"

# src/views/story/detail.ejs
cat << 'EOF' > childrens-story-app/src/views/story/detail.ejs
 <div class="bg-white p-8 rounded-lg shadow-md max-w-4xl mx-auto">
    <h1 class="text-3xl font-bold mb-4 text-gray-800"><%= story.title %></h1>
    <div class="text-gray-600 text-sm mb-4 border-b pb-3">
        <span class="mr-4">By: <strong class="text-gray-700"><%= story.author_username || 'Unknown Author' %></strong></span>
        <span class="mr-4">Difficulty: <strong class="text-gray-700"><%= story.difficulty %></strong></span>
        <span>Created: <strong class="text-gray-700"><%= new Date(story.created_at).toLocaleDateString() %></strong></span>
    </div>

    <!-- Using prose class for basic typography styling if Tailwind Typography plugin is used -->
    <!-- Otherwise, style paragraphs, etc., manually -->
    <div class="prose prose-lg max-w-none mt-6 mb-6 text-gray-700 leading-relaxed">
        <% story.content.split('\n').forEach(paragraph => { %>
            <% if (paragraph.trim()) { %>
                <p><%= paragraph %></p>
            <% } %>
        <% }); %>
    </div>

    <div class="flex justify-between items-center border-t pt-4 mt-6">
         <span class="text-gray-800 font-medium">Votes: <span id="vote-count-<%= story.id %>"><%= voteCount %></span></span>
         <% if (user) { %>
            <button
                class="vote-button <%= userVoted ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600' %> text-white font-bold py-2 px-4 rounded transition-colors duration-200"
                data-story-id="<%= story.id %>"
                <%= userVoted ? 'disabled' : '' %>
                id="vote-btn-<%= story.id %>">
                <%= userVoted ? 'Voted' : 'Vote Up' %>
            </button>
         <% } else { %>
            <p class="text-sm"><a href="/login?returnTo=/story/<%= story.id %>" class="text-blue-600 hover:underline">Login</a> to vote!</p>
         <% } %>
    </div>
</div>
 <!-- Include vote.js specifically for pages with vote buttons -->
<script src="/js/vote.js"></script>
EOF
echo "Created src/views/story/detail.ejs"

# src/views/story/create-step1.ejs
cat << 'EOF' > childrens-story-app/src/views/story/create-step1.ejs
<div class="max-w-2xl mx-auto bg-white p-8 rounded-lg shadow-md mt-10">
    <h1 class="text-2xl font-bold mb-6 text-center">Create a New Story - Step 1</h1>
    <p class="text-gray-600 mb-6 text-center">Tell us about the story you want to create!</p>

    <form action="/create-story/generate" method="POST">
        <!-- IMPORTANT: CSRF Token -->
        <input type="hidden" name="_csrfToken" value="<%= csrfToken %>">

        <div class="mb-4">
            <label for="theme" class="block text-gray-700 text-sm font-bold mb-2">Story Theme:</label>
            <textarea id="theme" name="theme" rows="3" required
                      class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.theme ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                      placeholder="e.g., A brave knight rescues a lost puppy, A magical adventure in a candy land"><%= typeof formData !== 'undefined' && formData.theme ? formData.theme : '' %></textarea>
            <% if (typeof errors !== 'undefined' && errors.theme) { %>
                <p class="text-red-500 text-xs italic mt-1"><%= errors.theme %></p>
            <% } %>
        </div>

        <div class="mb-4">
            <label for="characters" class="block text-gray-700 text-sm font-bold mb-2">Main Characters:</label>
            <textarea id="characters" name="characters" rows="3" required
                      class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.characters ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                      placeholder="e.g., Sir Reginald the Brave, Sparky the puppy, Princess Lolly"><%= typeof formData !== 'undefined' && formData.characters ? formData.characters : '' %></textarea>
             <% if (typeof errors !== 'undefined' && errors.characters) { %>
                <p class="text-red-500 text-xs italic mt-1"><%= errors.characters %></p>
            <% } %>
        </div>

        <div class="mb-6">
            <label for="difficulty" class="block text-gray-700 text-sm font-bold mb-2">Reading Difficulty:</label>
            <select id="difficulty" name="difficulty" required
                    class="shadow appearance-none border <%= typeof errors !== 'undefined' && errors.difficulty ? 'border-red-500' : 'border-gray-300' %> rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline bg-white">
                <option value="" disabled <%= typeof formData === 'undefined' || !formData.difficulty ? 'selected' : '' %>>Select Difficulty</option>
                <option value="Easy" <%= typeof formData !== 'undefined' && formData.difficulty === 'Easy' ? 'selected' : '' %>>Easy</option>
                <option value="Medium" <%= typeof formData !== 'undefined' && formData.difficulty === 'Medium' ? 'selected' : '' %>>Medium</option>
                <option value="Hard" <%= typeof formData !== 'undefined' && formData.difficulty === 'Hard' ? 'selected' : '' %>>Hard</option>
            </select>
             <% if (typeof errors !== 'undefined' && errors.difficulty) { %>
                <p class="text-red-500 text-xs italic mt-1"><%= errors.difficulty %></p>
            <% } %>
        </div>

        <div class="flex items-center justify-center">
            <button type="submit" class="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-6 rounded focus:outline-none focus:shadow-outline">
                Generate Story Draft
            </button>
        </div>
    </form>
</div>
EOF
echo "Created src/views/story/create-step1.ejs"

# src/views/story/create-review.ejs
cat << 'EOF' > childrens-story-app/src/views/story/create-review.ejs
<div class="max-w-3xl mx-auto bg-white p-8 rounded-lg shadow-md mt-10">
    <h1 class="text-2xl font-bold mb-4 text-center">Review Your Story Draft</h1>
    <p class="text-gray-600 mb-6 text-center">Read the story generated by the AI. You can approve it or try regenerating.</p>

    <div class="border rounded p-6 mb-6 bg-gray-50 max-h-96 overflow-y-auto">
        <h2 class="text-xl font-semibold mb-3">Generated Story (Attempt <%= attempt %> of <%= maxAttempts %>)</h2>
        <div class="prose max-w-none text-gray-800">
             <% storyContent.split('\n').forEach(paragraph => { %>
                <% if (paragraph.trim()) { %>
                    <p><%= paragraph %></p>
                <% } %>
            <% }); %>
        </div>
    </div>

    <div class="flex justify-between items-center">
        <!-- Approve and Save Form -->
        <form action="/api/stories/create" method="POST" class="inline">
            <input type="hidden" name="_csrfToken" value="<%= csrfToken %>">
            <button type="submit" class="bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                Approve and Save
            </button>
        </form>

        <!-- Regenerate Form -->
        <% if (canRegenerate) { %>
            <form action="/create-story/regenerate" method="POST" class="inline">
                <input type="hidden" name="_csrfToken" value="<%= csrfToken %>">
                <button type="submit" class="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                    Regenerate (<%= maxAttempts - attempt %> left)
                </button>
            </form>
        <% } else { %>
            <button type="button" class="bg-gray-400 text-white font-bold py-2 px-4 rounded cursor-not-allowed" disabled>
                Max Regenerations Reached
            </button>
        <% } %>

        <!-- Cancel/Start Over Link -->
         <a href="/create-story/start" class="text-red-500 hover:text-red-700 font-bold py-2 px-4 rounded border border-red-500 hover:bg-red-100">
            Cancel / Start Over
        </a>
    </div>
</div>
EOF
echo "Created src/views/story/create-review.ejs"

# --- public/css ---

# src/input.css (Source for Tailwind)
cat << 'EOF' > childrens-story-app/src/input.css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Add any custom base styles or components here if needed */
body {
    @apply text-gray-800;
}

/* Example: Style generated story content if not using prose plugin */
/*
.story-content p {
    @apply mb-4;
}
*/
EOF
echo "Created src/input.css"

# public/css/styles.css (Will be generated by Tailwind)
touch childrens-story-app/public/css/styles.css
echo "Created empty public/css/styles.css (will be built)"

# --- public/js ---

# public/js/main.js
cat << 'EOF' > childrens-story-app/public/js/main.js
// Add basic client-side validation feedback if needed
document.addEventListener('DOMContentLoaded', () => {
  // Example: Password match validation on registration form
  const registerForm = document.getElementById('register-form'); // Add id="register-form" to your form
  if (registerForm) {
    const password = registerForm.querySelector('#password');
    const confirmPassword = registerForm.querySelector('#confirmPassword');
    const confirmPasswordError = document.getElementById('confirmPasswordError'); // Add <p id="confirmPasswordError" class="text-red-500 text-xs italic mt-1"></p>

    const validatePasswordMatch = () => {
      if (!password || !confirmPassword) return; // Elements might not exist

      if (password.value && confirmPassword.value && password.value !== confirmPassword.value) {
        confirmPassword.classList.add('border-red-500');
        if(confirmPasswordError) confirmPasswordError.textContent = 'Passwords do not match.';
      } else {
        confirmPassword.classList.remove('border-red-500');
         if(confirmPasswordError) confirmPasswordError.textContent = '';
      }
    };

    if (password && confirmPassword) {
        password.addEventListener('input', validatePasswordMatch);
        confirmPassword.addEventListener('input', validatePasswordMatch);
    }
  }

  // Add more client-side validation as needed (e.g., required fields)
  // Note: Server-side validation is the source of truth.

  // Simple dismiss for flash messages
  const closeButtons = document.querySelectorAll('[role="alert"] button');
  closeButtons.forEach(button => {
      button.addEventListener('click', (e) => {
          e.target.closest('[role="alert"]').remove();
      });
  });

});
EOF
echo "Created public/js/main.js"

# public/js/vote.js
cat << 'EOF' > childrens-story-app/public/js/vote.js
document.addEventListener('DOMContentLoaded', () => {
    const voteButtons = document.querySelectorAll('.vote-button');

    // Function to get CSRF token from cookie (needed for fetch)
    function getCsrfToken() {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            let cookie = cookies[i].trim();
            // Does this cookie string begin with the name we want?
            if (cookie.startsWith('_csrfToken=')) {
                // Return only the value part
                return decodeURIComponent(cookie.substring('_csrfToken='.length));
            }
        }
        console.warn('CSRF token cookie not found.');
        return null; // Token not found
    }

    voteButtons.forEach(button => {
        button.addEventListener('click', async (event) => {
            const storyId = button.dataset.storyId;
            const csrfToken = getCsrfToken(); // Get token from cookie

            if (!storyId || button.disabled) {
                return; // Ignore if no ID or already disabled
            }
             if (!csrfToken) {
                console.error('CSRF token not found. Cannot vote.');
                // Provide user feedback - an alert might be too intrusive, consider a non-modal message
                // For simplicity, alert is used here.
                alert('Security token missing. Please refresh the page and try again.');
                return;
            }


            // Disable button immediately to prevent double clicks
            button.disabled = true;
            const originalText = button.textContent; // Store original text
            button.textContent = 'Voting...';
            button.classList.remove('bg-blue-500', 'hover:bg-blue-600');
            button.classList.add('bg-gray-400', 'cursor-not-allowed');

            try {
                const response = await fetch(`/api/stories/${storyId}/vote`, {
                    method: 'POST',
                    headers: {
                        // 'Content-Type': 'application/json', // Not strictly needed if body is empty
                        'X-CSRF-Token': csrfToken // Send token in header
                    },
                    // body: JSON.stringify({}) // Send empty body if needed, or add data
                });

                const result = await response.json(); // Always expect JSON back

                if (response.ok && result.success) {
                    // Success (either new vote or already voted)
                    button.textContent = 'Voted';
                    // Keep it disabled and grayed out
                    console.log(`Vote successful for story ${storyId}: ${result.message}`);

                    // Optionally update vote count display dynamically
                    const countElement = document.getElementById(`vote-count-${storyId}`);
                    if (countElement) {
                       // A simple but potentially inaccurate way: increment if status was 201 (Created)
                       if (response.status === 201) {
                           const currentCount = parseInt(countElement.textContent, 10);
                           if (!isNaN(currentCount)) {
                               countElement.textContent = currentCount + 1;
                           }
                       }
                       // More robust: fetch the new count, or use WebSockets.
                       // For this example, we just update the button text.
                    }
                } else {
                    // Handle specific errors
                     button.disabled = false; // Re-enable button on error
                     button.textContent = originalText; // Restore original text
                     button.classList.remove('bg-gray-400', 'cursor-not-allowed');
                     // Restore original classes if needed (e.g., blue background)
                     if (originalText === 'Vote Up') {
                         button.classList.add('bg-blue-500', 'hover:bg-blue-600');
                     }

                    if (response.status === 401 || response.status === 403) {
                        // 403 could also be CSRF failure
                        if (result.message && result.message.toLowerCase().includes('token')) {
                             alert(`Security error: ${result.message}. Please refresh and try again.`);
                        } else {
                             alert('Authentication error. Please log in again.');
                             window.location.href = '/login'; // Redirect to login
                        }
                    } else {
                        // General error
                        alert(`Failed to vote: ${result.message || 'Unknown error'}`);
                    }
                     console.error(`Vote failed for story ${storyId}: Status ${response.status}, Message: ${result.message}`);
                }

            } catch (error) {
                console.error('Network error during vote:', error);
                alert('Network error. Could not submit vote.');
                // Re-enable button on network failure
                button.disabled = false;
                button.textContent = originalText;
                button.classList.remove('bg-gray-400', 'cursor-not-allowed');
                 if (originalText === 'Vote Up') {
                    button.classList.add('bg-blue-500', 'hover:bg-blue-600');
                 }
            }
        });
    });
});
EOF
echo "Created public/js/vote.js"

# --- Create .env ---
echo "Creating .env file..."
# Generate a random secret
SESSION_SECRET_VALUE=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

# Check if GEMINI_API_KEY is set in the environment
if [ -z "$GEMINI_API_KEY" ]; then
  echo "WARNING: GEMINI_API_KEY environment variable is not set."
  echo "Story generation will fail. Please set it manually in the .env file."
  GEMINI_API_KEY_VALUE="your_gemini_api_key_here"
else
  echo "Using GEMINI_API_KEY from environment."
  GEMINI_API_KEY_VALUE="$GEMINI_API_KEY"
fi

cat << EOF > childrens-story-app/.env
NODE_ENV=development
PORT=3000
# IMPORTANT: This is a randomly generated secret. Keep it safe!
SESSION_SECRET=${SESSION_SECRET_VALUE}
DATABASE_URL=file:./data/dev.db
# IMPORTANT: Ensure this key is correct and kept secret.
GEMINI_API_KEY=${GEMINI_API_KEY_VALUE}
EOF
echo "Created .env with generated SESSION_SECRET and GEMINI_API_KEY."
echo "*** IMPORTANT: Review the .env file, especially the GEMINI_API_KEY! ***"

# --- Installation and Setup ---
echo "Running installation and setup steps..."
cd childrens-story-app

echo "Installing dependencies..."
npm install

echo "Initializing database schema..."
npm run db:init

echo "Building Tailwind CSS..."
npm run build:css

echo "Setup complete."
echo "You can now start the application in development mode by running:"
echo "cd childrens-story-app"
echo "npm run dev"
echo ""
echo "Starting the application in development mode now..."

# Launch in development mode
npm run dev
