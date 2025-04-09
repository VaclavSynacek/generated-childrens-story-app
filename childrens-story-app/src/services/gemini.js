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
