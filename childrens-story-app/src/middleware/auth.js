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
