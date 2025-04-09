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
