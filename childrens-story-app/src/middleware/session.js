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
