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
