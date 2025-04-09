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
