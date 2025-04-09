**System Specification: Children's Story Application**

**Version:** 1.1 - Final
**Date:** 2024-03-08

**IMPORTANT CONSTRAINTS:**

*   **Cryptography:** All cryptographic operations (hashing, signing, random number generation) **MUST** be implemented solely using the standard Node.js `crypto` module. No third-party cryptography libraries (e.g., `bcrypt`, `argon2`) are permitted. Standard algorithms like SHA-256/SHA-512 combined with cryptographically secure salting (for hashing) and HMAC (for signing/session cookies) must be used.
*   **Session Management:** Session management **MUST NOT** rely on third-party session middleware packages (e.g., `express-session`, `iron-session`). A custom solution using standard Node.js capabilities (e.g., signed cookies via `crypto.createHmac`) must be implemented. A strong, randomly generated `SESSION_SECRET` managed via environment variables is required for signing cookies.
*   **Language:** The application **MUST** be written entirely in vanilla JavaScript (ES6+ features compatible with the target Node.js version are acceptable). TypeScript is **NOT** permitted.
*   **Dependencies:** Dependency usage should be minimized. The core database interaction **MUST** use the `sqlite3` package. Frameworks like Express.js or Next.js (configured for vanilla JS output) are permitted but must be scrutinized. Any other third-party dependencies **MUST** be strictly vetted to ensure they do not introduce prohibited cryptography or session management libraries transitively.

**1. Introduction**

This document outlines the specifications for a public-facing web application designed to provide children with accessible and engaging stories. The application will allow unregistered users to read stories and register for an account. Registered users will have the added ability to vote on stories and generate new content using AI.

The application will be built using **Node.js** (targeting a recent LTS version, e.g., 18.x or 20.x) and implemented entirely in **vanilla JavaScript**. It may utilize a framework like Express.js or Next.js (configured for vanilla JS output). Styling will be achieved using Tailwind CSS. It will run in a standard Node.js environment and utilize a local SQLite database file for data persistence, accessed via the standard `sqlite3` Node.js package. All cryptographic functions (password hashing, session signing) **MUST** use the built-in Node.js `crypto` module. Session management will rely on custom-implemented signed cookies. Vote counts will be calculated dynamically by querying the `Votes` table.

**2. Goals**

*   Provide a user-friendly, accessible platform for children to read stories, built with vanilla JavaScript.
*   Enable registered users to contribute by voting on stories and generating new AI-assisted content.
*   Utilize standard Node.js modules (`crypto`, `sqlite3`) for core security and data persistence functions.
*   Ensure the application runs reliably in a standard Node.js environment.
*   Maintain data integrity and performance by calculating vote counts directly from vote records using optimized queries.

**3. Target Audience**

*   Children (primary audience for reading stories)
*   Parents/Educators (seeking content for children)
*   Registered Users (contributing and engaging with the platform)

**4. Use Cases**

**4.1. Unregistered Users**

*   **UC-1: Browse Stories (Index Page)**
    *   **Description:** Any visitor can access the index page, which lists all available stories sorted by popularity (vote count).
    *   **Pre-Conditions:** None.
    *   **Post-Conditions:** User is presented with a list of story titles, brief summaries, and dynamically calculated vote counts.
    *   **Steps:**
        1.  User navigates to the application's root URL (`/`).
        2.  The application server (Node.js) prepares to fetch story data.
        3.  The application retrieves story data from the `Stories` table in the SQLite database using the `sqlite3` package.
        4.  For each story (or preferably via a single optimized query joining `Stories` and `Votes`), the application calculates the vote count by counting the corresponding records in the `Votes` table (e.g., `SELECT s.id, s.title, s.content, COUNT(v.story_id) as vote_count FROM stories s LEFT JOIN votes v ON s.id = v.story_id GROUP BY s.id ORDER BY vote_count DESC`). Parameterized queries MUST be used.
        5.  The application renders the index page, displaying a list of stories, sorted by the calculated `vote_count` in descending order.
        6.  Each story listing includes its `title`, a short description/excerpt (e.g., first 100 characters of `content`), and the current calculated `vote_count`.
        7.  Each story listing is a hyperlink navigating the user to the story detail page (UC-2) using the story's unique identifier (e.g., `/story/{story_id}`).
        8.  The page header includes clearly visible links to "Register" (UC-3) and "Login" (UC-4).
    *   **Error Conditions:**
        *   Network error preventing client-server communication: Display a user-friendly message like "Unable to load stories. Please check your connection and try again."
        *   Database access error or query failure on the server: Log the detailed error server-side. Display a generic user-friendly message like "An error occurred while retrieving stories. Please try again later."

*   **UC-2: Read Story Detail**
    *   **Description:** Any visitor can view the full content of a selected story.
    *   **Pre-Conditions:** User has a valid story identifier (e.g., from UC-1).
    *   **Post-Conditions:** User is presented with the full story content and related metadata, including the dynamically calculated vote count.
    *   **Steps:**
        1.  User navigates to a story detail URL (e.g., `/story/{story_id}`).
        2.  The application server retrieves the specific story data from the `Stories` table using the provided `story_id` via a parameterized query (`sqlite3`). It also retrieves the author's `username` by joining with the `Users` table based on `author_id`.
        3.  The application calculates the vote count for this specific story by querying the `Votes` table (e.g., `SELECT COUNT(*) FROM votes WHERE story_id = ?` using the `story_id`, via `sqlite3` parameterized query).
        4.  If the story is found, the application renders the story detail page displaying:
            *   Story `title`.
            *   Author's `username`.
            *   Full story `content`.
            *   Current calculated vote count.
            *   Difficulty level (`difficulty`).
        5.  The page includes clearly visible links/buttons to the registration page (UC-3, e.g., `/register`) and the login page (UC-4, e.g., `/login`).
    *   **Error Conditions:**
        *   Network error preventing client-server communication: Display a user-friendly message like "Unable to load the story. Please check your connection and try again."
        *   Database access error or query failure on the server: Log the detailed error server-side. Display a generic user-friendly message like "An error occurred while retrieving the story. Please try again later."
        *   Story not found (`story_id` does not exist): Respond with HTTP 404 status. Display a dedicated "Story Not Found" page with a clear message and a link back to the index page (UC-1).

*   **UC-3: Register New User**
    *   **Description:** Unregistered users can create a new account.
    *   **Pre-Conditions:** User is not logged in.
    *   **Post-Conditions:** A new user record is created in the SQLite database. The user is redirected to the login page with a success message.
    *   **Steps:**
        1.  User navigates to the registration page (e.g., `/register`).
        2.  The application displays a registration form with the following fields:
            *   Username (input type text, required, constraints: alphanumeric, underscores, length 3-20).
            *   Password (input type password, required, minimum 8 characters).
            *   Confirm Password (input type password, required, must match Password field).
            *   Email Address (input type email, required, must be a valid email format).
        3.  User fills in the form and clicks the "Register" or "Sign Up" button.
        4.  Client-side validation (using **vanilla JavaScript**) provides immediate feedback for empty required fields, password mismatch, and basic email format validation.
        5.  Upon form submission, the server-side logic (in **vanilla JavaScript**) performs rigorous validation:
            *   Checks for empty required fields.
            *   Verifies username format and length.
            *   Verifies username uniqueness against the `Users` table (case-insensitive check recommended).
            *   Verifies email uniqueness against the `Users` table (case-insensitive check recommended).
            *   Validates email format using a robust regular expression.
            *   Ensures password meets length requirements (minimum 8 characters).
            *   Confirms passwords match.
        6.  If server-side validation fails, re-render the registration page displaying specific, user-friendly error messages next to the corresponding fields (e.g., "Username already taken", "Email already registered", "Passwords do not match", "Password must be at least 8 characters long"). Retain non-password field values (username, email).
        7.  If server-side validation is successful:
            *   Generate a cryptographically secure unique salt (e.g., 16 bytes) using `crypto.randomBytes`. Encode it (e.g., hex or base64) for storage.
            *   Generate a secure hash of the user's password combined with the salt using a standard Node.js `crypto` function (e.g., `crypto.pbkdf2Sync` with sufficient iterations, or `crypto.createHmac('sha512', salt).update(password).digest('hex')`). **Never store plain text passwords.**
            *   Create a new user record in the `Users` table using a `sqlite3` parameterized query, storing the `username`, `email`, the generated password `password_hash`, and the generated `salt`.
            *   Redirect the user to the login page (UC-4) with a success message displayed on that page: "Registration successful! Please log in."
    *   **Error Conditions:**
        *   Network error during form submission: Display a user-friendly message like "Registration failed due to a network issue. Please try again."
        *   Database access error or insertion failure on the server: Log the detailed error server-side. Display a generic user-friendly message: "An error occurred during registration. Please try again later."
        *   Validation errors (as described in step 6).

*   **UC-4: Login**
    *   **Description:** Users with existing accounts can log in to access authenticated features.
    *   **Pre-Conditions:** User has a registered account. User is not logged in.
    *   **Post-Conditions:** User session is established via a signed cookie, user is authenticated, and redirected to the index page.
    *   **Steps:**
        1.  User navigates to the login page (e.g., `/login`).
        2.  The application displays a login form with the following fields:
            *   Username or Email (input type text, required).
            *   Password (input type password, required).
        3.  User enters their credentials and clicks the "Login" or "Sign In" button.
        4.  Upon submission, the server-side logic (in **vanilla JavaScript**) performs authentication:
            *   Retrieve the user record (including `id`, `password_hash`, `salt`) from the `Users` table based on the provided username or email (case-insensitive lookup recommended) using a `sqlite3` parameterized query.
            *   If no user is found matching the username/email, proceed immediately to step 5 (authentication failure).
            *   If a user is found, hash the *provided* password using the *same* algorithm (e.g., `crypto.pbkdf2Sync` or `crypto.createHmac`) and the *retrieved salt* from the database.
            *   Perform a **timing-safe comparison** between the newly generated hash and the stored `password_hash` using `crypto.timingSafeEqual`. Convert hashes to buffers if necessary for the comparison.
        5.  If authentication fails (user not found OR password hash mismatch), re-render the login page with a generic error message: "Invalid username/email or password." Do **not** indicate whether the username/email exists or if the password was wrong.
        6.  If authentication is successful:
            *   Establish a user session using **custom signed cookie management**:
                *   Create a session payload object (e.g., `{ userId: user.id, username: user.username, issuedAt: Date.now() }`). Add an expiration if desired.
                *   Serialize the payload (e.g., `JSON.stringify`).
                *   Create a signature for the payload using `crypto.createHmac('sha256', process.env.SESSION_SECRET).update(serializedPayload).digest('hex')`. The `SESSION_SECRET` **MUST** be a strong, secret key loaded from environment variables.
                *   Set a secure, HttpOnly cookie (e.g., named `session`) containing the serialized payload and the signature (e.g., `payload.signature`). Ensure the `Secure` flag is set if using HTTPS (mandatory for production). Set `SameSite=Lax` or `SameSite=Strict`.
            *   Redirect the user to the index page (UC-5).
    *   **Error Conditions:**
        *   Network error during form submission: Display a user-friendly message like "Login failed due to a network issue. Please try again."
        *   Database access error or query failure on the server: Log the detailed error server-side. Display a generic user-friendly message: "An error occurred during login. Please try again later."
        *   Authentication failure (as described in step 5).
        *   Missing `SESSION_SECRET` environment variable: Log critical error server-side. Prevent login attempts.

**4.2. Logged-in Users**

*   **UC-5: Browse Stories (Index Page) - Logged-in User**
    *   **Description:** Logged-in users browse the list of stories with additional UI elements for interaction (voting).
    *   **Pre-Conditions:** User is logged in (possesses a valid, verifiable signed session cookie).
    *   **Post-Conditions:** User is presented with the list of stories, including voting controls reflecting their vote status, and dynamically calculated vote counts.
    *   **Steps:**
        1.  User navigates to the application's root URL (`/`).
        2.  The application server identifies the user by **validating the signed session cookie**:
            *   Read the session cookie (e.g., `session`).
            *   Parse the cookie value to separate the serialized payload and the signature.
            *   Re-calculate the signature for the received payload using `crypto.createHmac('sha256', process.env.SESSION_SECRET).update(serializedPayload).digest('hex')`.
            *   Perform a **timing-safe comparison** (`crypto.timingSafeEqual`) between the calculated signature and the received signature.
            *   If signatures match (and payload hasn't expired, if applicable), extract the `userId` and `username` from the payload. Authentication is successful.
            *   If validation fails (missing cookie, signature mismatch, expired), treat the user as logged out (redirect to login or proceed as UC-1). Clear the invalid cookie.
        3.  The application retrieves story data similarly to UC-1, but also joins with the `Votes` table filtered by the validated `userId` to determine if the current user has voted on each story (e.g., `SELECT ..., CASE WHEN v_user.user_id IS NOT NULL THEN 1 ELSE 0 END as user_voted FROM stories s ... LEFT JOIN votes v_user ON s.id = v_user.story_id AND v_user.user_id = ? ...`, passing the `userId`).
        4.  Vote counts are calculated as in UC-1.
        5.  The application renders the index page, displaying stories sorted by vote count.
        6.  Each story listing includes:
            *   `title`.
            *   Short description/excerpt.
            *   Current calculated vote count.
            *   A "Vote Up" button (UC-6a). This button should be visually distinct (e.g., disabled or showing an "Already Voted" state) if the `user_voted` flag from the query (step 3) indicates the logged-in user has already voted for that story.
        7.  Each story listing is a hyperlink to the story detail page (UC-6).
        8.  The page header/navigation indicates the user is logged in (e.g., displaying `username`) and provides links to "Create Story" (UC-7) and "Logout" (UC-8). Links for "Register" and "Login" are hidden.
    *   **Error Conditions:** Same as UC-1. Add: Session validation failure leads to logged-out view (UC-1) or redirect to login (UC-4).

*   **UC-6: Read Story Detail - Logged-in User**
    *   **Description:** Logged-in users view the full story content and can interact by voting.
    *   **Pre-Conditions:** User is logged in (valid session cookie). User has a valid story identifier.
    *   **Post-Conditions:** User is presented with the full story content and voting controls reflecting their vote status, with dynamically calculated vote count.
    *   **Steps:**
        1.  User navigates to a story detail URL (e.g., `/story/{story_id}`).
        2.  The application server validates the user's session cookie (as described in UC-5, Step 2). If invalid, redirect to login or show UC-2 view.
        3.  Retrieve story data and author username as in UC-2.
        4.  Check if the current validated `user_id` has an entry in the `Votes` table for the current `story_id` using a `sqlite3` parameterized query (e.g., `SELECT 1 FROM votes WHERE user_id = ? AND story_id = ? LIMIT 1`).
        5.  Calculate the total vote count for this story as in UC-2.
        6.  If the story is found, render the detail page displaying:
            *   Story `title`.
            *   Author's `username`.
            *   Full story `content`.
            *   Current calculated vote count.
            *   Difficulty level (`difficulty`).
            *   A "Vote Up" button (UC-6a). This button is visually distinct (disabled/different style) if the query in step 4 indicates the user has already voted.
        7.  The page header/navigation includes links to "Create Story" (UC-7) and "Logout" (UC-8).
    *   **Error Conditions:** Same as UC-2. Add: Session validation failure leads to logged-out view (UC-2) or redirect to login (UC-4).

*   **UC-6a: Vote on Story**
    *   **Description:** Logged-in users can cast one vote per story. Voting is idempotent from the user's perspective after the first successful vote.
    *   **Pre-Conditions:** User is logged in (valid session cookie). User is viewing a story detail page (UC-6) or the story list (UC-5). The user has *not* already voted on this specific story (UI should ideally prevent clicking if already voted).
    *   **Post-Conditions:** A vote record is created in the `Votes` table if one doesn't exist for this user/story pair. The UI reflects the voted state. The displayed vote count updates upon subsequent page load or data refresh.
    *   **Steps:**
        1.  User clicks the "Vote Up" button associated with a specific story (`story_id`).
        2.  A client-side request (e.g., using `fetch` in **vanilla JavaScript**) is sent to a dedicated backend API endpoint (e.g., `POST /api/stories/{story_id}/vote`). The request must include the session cookie automatically.
        3.  The server-side API handler first validates the session cookie (as in UC-5, Step 2). If invalid, it returns an authentication error (e.g., HTTP 401 or 403).
        4.  If authenticated, the server attempts to insert a new record into the `Votes` table using a `sqlite3` parameterized query: `INSERT INTO votes (user_id, story_id) VALUES (?, ?)`. Use the validated `user_id` and the `story_id` from the URL parameter.
        5.  If the insertion is successful (a new vote was cast):
            *   Return a success response (e.g., HTTP 201 Created or 200 OK with a success message/status).
        6.  If the insertion fails due to a primary key constraint violation (meaning the `user_id`, `story_id` pair already exists):
            *   Treat this as success from the user's perspective (they intended to vote, and a vote exists). Return a success response (e.g., HTTP 200 OK, potentially indicating "already voted" if needed by the client). Avoid returning a conflict error like 409 unless specifically required, as the state is already achieved.
        7.  If the insertion fails for other database reasons (e.g., connection issue, constraint violation on foreign key):
            *   Log the detailed error server-side. Return a server error response (e.g., HTTP 500).
        8.  Upon receiving a success response (200 or 201), the client-side **vanilla JavaScript** updates the UI:
            *   Change the state of the "Vote Up" button for that story to indicate the user has now voted (e.g., disable it, change style/text).
            *   Optionally, trigger a re-fetch of the vote count or increment the displayed count locally (less accurate but faster feedback). A full data refresh is more robust.
        9.  Upon receiving an authentication error (401/403), redirect the user to the login page.
        10. Upon receiving a server error (500), display an unobtrusive error message (e.g., using a toast notification: "Failed to record vote. Please try again later.").
    *   **Error Conditions:**
        *   Network error during vote request: Client-side displays "Network error. Could not vote."
        *   Database access error/unexpected insertion failure on server: Log error. Server returns 500. Client displays generic error.
        *   User not authenticated: API returns 401/403; client redirects to login.
        *   User has already voted: API ideally returns 200 OK; client ensures button reflects voted state.

*   **UC-7: Story Creation Wizard**
    *   **Description:** Logged-in users use a multi-step process involving AI (Gemini) to generate and save new stories.
    *   **Pre-Conditions:** User is logged in (valid session cookie).
    *   **Post-Conditions:** A new story is saved to the SQLite database associated with the logged-in user.
    *   **Wizard State Management:** Temporary data between steps (theme, characters, difficulty, generated content, regeneration count) must be stored securely, associated with the user's session. This can be achieved by storing it server-side in memory (potentially lost on server restart) or a temporary database table, linked to the validated `userId`. Storing large amounts of data directly in the signed cookie is discouraged. *Decision: Use server-side temporary storage keyed by `userId`.*
    *   **Steps:**

        *   **7a: Navigate and Define Story Details:**
            1.  User navigates to the wizard start page (e.g., `/create-story/step-1`). Server validates session.
            2.  Display a form (rendered server-side) with fields: Story Theme (textarea, required), Story Characters (textarea, required), Story Difficulty (select/radio, required: "Easy", "Medium", "Hard").
            3.  User fills fields and clicks "Next" or "Generate Story".
            4.  Perform client-side validation (vanilla JS) for required fields.
            5.  On submission, server validates session again, validates required fields server-side.
            6.  If valid, store Theme, Characters, Difficulty in the server-side temporary storage associated with the `userId`. Initialize regeneration counter to 0. Redirect user to generation/review step (e.g., `/create-story/step-2`).
            7.  If invalid, re-render step 1 form with error messages.

        *   **7b: Generate Story via Gemini AI (Server-Side):**
            1.  User arrives at step 2 page (e.g., `/create-story/step-2`). Server validates session.
            2.  Server retrieves Theme, Characters, Difficulty from temporary storage using `userId`.
            3.  Server constructs a prompt for the Gemini AI using these details (e.g., "Write a short story for children with difficulty '{Difficulty}', featuring characters '{Characters}' based on the theme '{Theme}'.").
            4.  Server securely communicates with the Gemini API using the `GEMINI_API_KEY` (from environment variables) via HTTPS request. Handle potential errors (network, API key, rate limits, bad responses).
            5.  Server receives the generated story text from Gemini. Perform basic sanity checks (e.g., non-empty).
            6.  Store the generated story `content` in the server-side temporary storage for the `userId`. Increment the regeneration counter in temporary storage.
            7.  Redirect user to the review step (e.g., `/create-story/step-3`). Handle Gemini API errors by redirecting back to step 1 or showing an error page.

        *   **7c: Review and Approve/Regenerate Story:**
            1.  User arrives at review page (e.g., `/create-story/step-3`). Server validates session.
            2.  Server retrieves generated `content` and regeneration `counter` from temporary storage.
            3.  Display the generated story `content`.
            4.  Display regeneration attempt counter (e.g., "Attempt {counter} of 3").
            5.  Provide "Approve and Save" button (leads to step 7d) and "Regenerate" button.
            6.  If "Regenerate" is clicked:
                *   Server validates session. Checks `counter` against limit (e.g., max 3 total attempts).
                *   If limit not reached, redirect back to step 2 (which will trigger 7b again using the originally stored inputs).
                *   If limit reached, re-render the review page (step 7c) but disable the "Regenerate" button and show message "Maximum regeneration attempts reached."

        *   **7d: Save Approved Story (Server-Side):**
            1.  User clicks "Approve and Save" on the review page (step 7c).
            2.  Request sent to a dedicated save endpoint (e.g., `POST /api/stories/create`).
            3.  Server validates session. Retrieves approved `content`, original `theme`, `characters`, `difficulty` from temporary storage using `userId`.
            4.  Server generates a `title` for the story (e.g., first ~10 words of the `content`, stripping punctuation).
            5.  Server saves a new record to the `Stories` table using a `sqlite3` parameterized query, including: `title`, `content`, `author_id` (the validated `userId`), `difficulty`, `theme`, `characters`. **No `vote_count` column exists or is stored.**
            6.  Clear the temporary story data associated with the `userId`.
            7.  Redirect user to the index page (UC-5) with a success message: "Story created successfully!".

    *   **Error Conditions:**
        *   Session validation failure at any step: Redirect to login (UC-4).
        *   Network errors during client-server or server-Gemini communication: Display user-friendly messages. Log details server-side.
        *   Database access error during save (7d): Log error server-side. Display "Failed to save the story. Please try again." (Potentially redirect back to review step with data intact if possible).
        *   Gemini AI communication error (network, API key, etc.): Log details. Display "Error generating story: Could not connect to the AI service." Redirect user appropriately (e.g., back to step 1).
        *   Gemini AI response error/invalid content: Log details. Display "Error generating story: The AI service returned an unexpected response." Redirect user appropriately.
        *   Gemini AI rate limiting: Log error. Display "Story generation is temporarily unavailable. Please try again later." Redirect user appropriately.
        *   Validation errors (step 7a).
        *   Maximum regeneration attempts reached (step 7c).
        *   Failure to retrieve temporary data (e.g., session expired, data cleared): Redirect to step 1.

*   **UC-8: Logout**
    *   **Description:** Logged-in users can end their session.
    *   **Pre-Conditions:** User is logged in (valid session cookie exists).
    *   **Post-Conditions:** User session is invalidated (cookie cleared), user is no longer authenticated, user is redirected to the index page.
    *   **Steps:**
        1.  User clicks the "Logout" link/button.
        2.  A request (e.g., POST) is sent to a dedicated logout endpoint (e.g., `/api/logout`).
        3.  The server performs session destruction:
            *   Instruct the client to clear the session cookie by sending a `Set-Cookie` header with the same cookie name (`session`), an empty value, `HttpOnly`, `Secure` (if applicable), `SameSite` attributes, and an `Expires` date in the past (or `Max-Age=0`).
            *   If using server-side session storage, delete any temporary data associated with the user's session/ID.
        4.  Server redirects the user to the index page (UC-1).
    *   **Error Conditions:**
        *   Network error during logout request: Client UI might appear stuck; a page refresh should show the logged-out state. Server action likely still completes.
        *   Server error during session destruction (rare): Log error server-side. Proceed with redirect and cookie clearing instruction; the session is likely invalid anyway.

**5. Data Model (SQLite)**

*   The database is a single SQLite file stored on the server filesystem. The file path **MUST** be configurable via an environment variable (e.g., `DATABASE_URL=file:./data/prod.db`).
*   Database interaction **MUST** use the standard Node.js `sqlite3` package with parameterized queries to prevent SQL injection vulnerabilities. ORMs are discouraged due to the vanilla JS and dependency constraints.

*   **Users Table (`users`)**
    ```sql
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, -- Store hash from Node.js crypto (e.g., PBKDF2/HMAC-SHA result)
        salt TEXT NOT NULL,         -- Store unique salt (crypto.randomBytes output, hex/base64 encoded)
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP -- ISO8601 Format (YYYY-MM-DD HH:MM:SS.SSS)
    );
    CREATE INDEX idx_users_email ON users(email); -- For login lookup
    -- Unique index on username is implicitly created by UNIQUE constraint
    ```
    *   *Constraints:* `username` length/format checked in application logic. `email` format checked in application logic. Password complexity checked in application logic.

*   **Stories Table (`stories`)**
    ```sql
    CREATE TABLE stories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        author_id INTEGER,          -- REFERENCES users(id) ON DELETE SET NULL
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, -- ISO8601 Format
        difficulty TEXT NOT NULL CHECK(difficulty IN ('Easy', 'Medium', 'Hard')), -- Use CHECK constraint
        theme TEXT NOT NULL,
        characters TEXT NOT NULL,
        FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE INDEX idx_stories_author_id ON stories(author_id);
    CREATE INDEX idx_stories_created_at ON stories(created_at); -- If sorting/filtering by date is needed
    ```
    *   *Constraints:* `difficulty` constrained in schema. `title`, `content`, `theme`, `characters` non-empty checked in application logic.

*   **Votes Table (`votes`)**
    ```sql
    CREATE TABLE votes (
        user_id INTEGER NOT NULL, -- REFERENCES users(id) ON DELETE CASCADE
        story_id INTEGER NOT NULL, -- REFERENCES stories(id) ON DELETE CASCADE
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, -- ISO8601 Format
        PRIMARY KEY (user_id, story_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (story_id) REFERENCES stories(id) ON DELETE CASCADE
    );
    -- Crucial index for vote count calculation performance:
    CREATE INDEX idx_votes_story_id ON votes(story_id);
    -- The primary key implicitly covers (user_id, story_id) lookups.
    ```

**6. Technology Stack**

*   **Core Language:** Vanilla JavaScript (ES6+ features compatible with target Node.js LTS version)
*   **Backend Environment:** Node.js (Specify target LTS version, e.g., 20.x)
*   **Web Framework (Optional but Recommended):** Express.js (using vanilla JS) or Next.js (configured for vanilla JS output). If no framework, use Node.js `http` module directly.
*   **Styling:** Tailwind CSS (integrated via PostCSS or similar standard method).
*   **Database:** SQLite (local file).
*   **Database Interaction:** Node.js `sqlite3` package (**parameterized queries mandatory**).
*   **Cryptography & Sessions:** **Node.js `crypto` module ONLY**. Custom implementation for password hashing (PBKDF2 or HMAC-SHA + salt) and session management (HMAC-signed cookies). **No `bcrypt`, `iron-session`, `express-session`, etc.**
*   **AI Service:** Google Gemini generative AI (via its official REST API, called from server-side JS).

**7. API Endpoints (Conceptual - Adapt based on chosen framework)**

*   `/api/register` (POST): Handles UC-3. Consumes form data. Returns redirect or error messages.
*   `/api/login` (POST): Handles UC-4. Consumes form data. Sets signed session cookie on success. Returns redirect or error messages.
*   `/api/logout` (POST): Handles UC-8. Clears session cookie. Returns redirect.
*   `/api/stories` (GET): Serves data for UC-1/UC-5 (handled by page route rendering in Next.js/Express typically, not a separate API unless building SPA).
*   `/api/stories/[storyId]` (GET): Serves data for UC-2/UC-6 (handled by page route rendering).
*   `/api/stories/[storyId]/vote` (POST): Handles UC-6a. Requires valid session cookie. Returns success/error status.
*   `/api/stories/create` (POST): Handles UC-7d (saving story). Requires valid session cookie. Consumes form/JSON data. Returns redirect.
*   *(Internal endpoints/logic might exist for UC-7 steps, e.g., triggering Gemini generation, not necessarily exposed as public API endpoints)*
*   **Middleware:** Custom vanilla JS middleware function(s) required for validating the signed session cookie on protected routes/endpoints.

**8. User Interface (UI) / User Experience (UX) Design**

*   **General:** Clean, simple, visually appealing design suitable for children and accessible. Use large, readable fonts (WCAG compliant), high contrast, clear visual hierarchy, and intuitive navigation. Responsive design is essential (desktop, tablet, mobile). All interactive elements must be controllable via vanilla JavaScript.
*   **Index Page:** List of stories with title, truncated description, calculated vote count. "Vote Up" button state clearly reflects logged-in user's vote status (votable/already voted). Clear Login/Register links (for logged-out users) or Username/Create Story/Logout links (for logged-in users). Implement pagination if the story list becomes long.
*   **Story Detail Page:** Readable layout for story content. Clear display of title, author, calculated vote count, difficulty. Prominent "Vote Up" button with correct state for logged-in user.
*   **Registration/Login Pages:** Simple forms, clear labels, inline validation error messages displayed near the relevant fields. Password masking (`<input type="password">`) is standard; an optional visibility toggle implemented with vanilla JS is helpful.
*   **Story Creation Wizard:** Clear indication of current step in the multi-step process. User-friendly forms. Display a loading indicator (e.g., spinner) during AI generation (step 7b). Clear review step (7c) with easily identifiable "Approve and Save" and "Regenerate" buttons. Provide clear feedback on regeneration attempts remaining/limit reached.
*   **Error Handling:** Use non-intrusive notifications (e.g., toasts implemented with vanilla JS/CSS) for minor, transient errors (e.g., vote failed). Use inline messages for form validation errors. Use user-friendly full-page messages for major errors where recovery isn't possible (e.g., story not found 404, critical server error 500).

**9. Security Considerations**

*   **Authentication:**
    *   Password Hashing: Use Node.js `crypto.pbkdf2Sync` (with sufficient iterations, e.g., 10000+) or `crypto.createHmac('sha512', salt)` against the password concatenated with a unique, per-user salt (`crypto.randomBytes`, min 16 bytes, stored alongside hash). **Store only hash and salt.**
    *   Password Comparison: Use `crypto.timingSafeEqual` for comparing password hashes during login.
    *   Session Management: Use custom signed cookies. Sign session data using `crypto.createHmac` (`sha256` or stronger) with a strong, high-entropy secret key (`SESSION_SECRET`) loaded exclusively from environment variables and **never** hardcoded. Rotate this secret periodically. Set cookies with `HttpOnly`, `Secure` (in production/HTTPS), and `SameSite=Lax` (or `Strict`) attributes.
*   **Authorization:** Implement custom middleware (vanilla JS) to verify the session cookie signature and validity before allowing access to protected routes/endpoints or performing actions requiring login (voting, creating stories). Ensure actions are always bound to the `userId` extracted from the validated session, not from user input.
*   **Input Validation:** Rigorously validate and sanitize **all** user input on the server-side (using vanilla JS checks, regex, type checks) to prevent Cross-Site Scripting (XSS), improper data handling, etc. Validate data types, lengths, formats, and ranges.
*   **SQL Injection Prevention:** **Exclusively** use parameterized queries via the `sqlite3` package for all database interactions. Never concatenate user input directly into SQL strings.
*   **API Security:**
    *   Rate Limiting: Implement basic rate limiting (e.g., using in-memory counters per IP/userId keyed in an object or Map, or a dedicated DB table) on sensitive endpoints like login, register, vote, and story generation to mitigate brute-force and denial-of-service attempts.
    *   CSRF Protection: For actions initiated by forms or potentially sensitive client-side requests (like voting, story creation), implement CSRF protection. The double-submit cookie pattern (generating a random token via `crypto.randomBytes`, setting it in a cookie, and requiring it in a hidden form field or custom header for POST/PUT/DELETE requests) is a viable approach without server-side session state.
*   **AI API Key Security:** Store the `GEMINI_API_KEY` securely using environment variables on the server. **Never** expose this key in client-side code or commit it to version control. Communication with the Gemini API must happen only from the server-side.
*   **Dependencies:** Keep Node.js and allowed dependencies (`sqlite3`, framework if used, Tailwind CSS tooling) updated with security patches. **Actively verify** the dependency tree (`npm ls --production` or `yarn list --prod`) to ensure no prohibited crypto/session libraries or known vulnerable packages are included transitively.
*   **HTTPS:** Configure the deployment environment (e.g., via a reverse proxy like Nginx) to serve the application exclusively over HTTPS to protect data in transit, including session cookies.
*   **SQLite Security:** Ensure the SQLite database file and its containing directory have appropriate, minimal filesystem permissions (writable only by the Node.js process user). Implement a regular, automated backup strategy for the database file, storing backups securely off-server. Be aware of SQLite's write concurrency limitations under high load.
*   **Error Handling:** Log detailed errors server-side only. Provide generic, non-revealing error messages to the client.

**10. Deployment Process (Generic Node.js Environment)**

1.  **Environment Setup:** Target server requires Node.js (specified LTS version) and npm/yarn. Ensure necessary build tools (like Git) are present.
2.  **Configuration:** Set required environment variables on the server:
    *   `NODE_ENV=production`
    *   `PORT` (e.g., 3000)
    *   `DATABASE_URL=file:/path/to/your/database/prod.db` (Ensure path is correct and directory exists/is writable by the Node process).
    *   `GEMINI_API_KEY` (Securely obtained Gemini key).
    *   `SESSION_SECRET` (A strong, randomly generated secret string, e.g., using `crypto.randomBytes(32).toString('hex')`).
3.  **Code Deployment:** Deploy application code to the server (e.g., via Git clone/pull).
4.  **Dependencies:** Navigate to the application directory and run `npm install --production` (or `yarn install --production`). **Verify dependency tree** for compliance after installation.
5.  **Build (If Applicable):** If using Next.js or Tailwind CSS requires a build step, run it (e.g., `npm run build`).
6.  **Database Migration/Setup:** Run necessary SQL scripts (using `sqlite3` CLI or a custom migration script) to create/update the schema in the SQLite file specified by `DATABASE_URL`. Ensure the initial schema matches Section 5.
7.  **Run Application:** Start the Node.js server application (e.g., `node server.js` or `npm start` / `yarn start` if defined in `package.json`).
8.  **Process Management:** Use a process manager like PM2 or systemd to run the Node.js application as a background service. This handles daemonization, logging, automatic restarts on crashes, and potentially clustering.
9.  **Web Server/Reverse Proxy (Highly Recommended):** Configure a web server like Nginx or Apache in front of the Node.js application. Configure it to:
    *   Listen on ports 80/443.
    *   Terminate SSL/TLS (handle HTTPS).
    *   Proxy requests to the Node.js application running on its internal port (e.g., 3000).
    *   Optionally serve static assets directly for better performance.
    *   Set appropriate security headers (e.g., HSTS, CSP).
10. **Backup Strategy:** Implement regular, automated backups of the SQLite database file (`prod.db`). Store backups securely and ideally off-site.

**11. Performance Considerations**

*   **Vote Count Calculation:** The dynamic calculation of vote counts, especially for the sorted index page, is a potential bottleneck. The query provided in UC-1 (using `LEFT JOIN` and `GROUP BY`) combined with the **essential index on `votes.story_id`** is designed for this. Monitor query performance under load.
*   **Indexing:** Ensure all necessary database indexes (as defined in Section 5) are created. Use `EXPLAIN QUERY PLAN` in SQLite to verify queries are using indexes effectively, particularly for vote counts and user lookups.
*   **Database Concurrency:** Be mindful that SQLite has limited write concurrency (typically one writer at a time per database file). If high concurrent write load (many simultaneous votes or story creations) becomes an issue, strategies like queuing writes or potentially moving to a different database system might be necessary in future versions. Read performance is generally very good.
*   **AI Latency:** Calls to the external Gemini API (UC-7b) will introduce latency. Provide clear loading indicators to the user during this step. Implement reasonable timeouts and error handling for API calls.
*   **Caching:** If read performance becomes insufficient under heavy load, consider server-side caching strategies for frequently accessed, relatively static data (like story lists or calculated vote counts), accepting a potential slight delay in displaying the absolute latest counts. Implement cache invalidation logic carefully (e.g., invalidate story list cache when a new story is created or voted on). Use simple in-memory caching (e.g., Node.js Map with TTL) initially.
*   **Client-Side JavaScript:** Keep client-side vanilla JavaScript efficient. Avoid complex DOM manipulations in large loops. Optimize event handlers.
