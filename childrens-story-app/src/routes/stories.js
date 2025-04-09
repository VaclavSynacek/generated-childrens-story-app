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
