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
