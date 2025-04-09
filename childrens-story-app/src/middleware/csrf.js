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
