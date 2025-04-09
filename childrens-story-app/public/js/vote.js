document.addEventListener('DOMContentLoaded', () => {
    const voteButtons = document.querySelectorAll('.vote-button');

    // Function to get CSRF token from cookie (needed for fetch)
    function getCsrfToken() {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            let cookie = cookies[i].trim();
            // Does this cookie string begin with the name we want?
            if (cookie.startsWith('_csrfToken=')) {
                // Return only the value part
                return decodeURIComponent(cookie.substring('_csrfToken='.length));
            }
        }
        console.warn('CSRF token cookie not found.');
        return null; // Token not found
    }

    voteButtons.forEach(button => {
        button.addEventListener('click', async (event) => {
            const storyId = button.dataset.storyId;
            const csrfToken = getCsrfToken(); // Get token from cookie

            if (!storyId || button.disabled) {
                return; // Ignore if no ID or already disabled
            }
             if (!csrfToken) {
                console.error('CSRF token not found. Cannot vote.');
                // Provide user feedback - an alert might be too intrusive, consider a non-modal message
                // For simplicity, alert is used here.
                alert('Security token missing. Please refresh the page and try again.');
                return;
            }


            // Disable button immediately to prevent double clicks
            button.disabled = true;
            const originalText = button.textContent; // Store original text
            button.textContent = 'Voting...';
            button.classList.remove('bg-blue-500', 'hover:bg-blue-600');
            button.classList.add('bg-gray-400', 'cursor-not-allowed');

            try {
                const response = await fetch(`/api/stories/${storyId}/vote`, {
                    method: 'POST',
                    headers: {
                        // 'Content-Type': 'application/json', // Not strictly needed if body is empty
                        'X-CSRF-Token': csrfToken // Send token in header
                    },
                    // body: JSON.stringify({}) // Send empty body if needed, or add data
                });

                const result = await response.json(); // Always expect JSON back

                if (response.ok && result.success) {
                    // Success (either new vote or already voted)
                    button.textContent = 'Voted';
                    // Keep it disabled and grayed out
                    console.log(`Vote successful for story ${storyId}: ${result.message}`);

                    // Optionally update vote count display dynamically
                    const countElement = document.getElementById(`vote-count-${storyId}`);
                    if (countElement) {
                       // A simple but potentially inaccurate way: increment if status was 201 (Created)
                       if (response.status === 201) {
                           const currentCount = parseInt(countElement.textContent, 10);
                           if (!isNaN(currentCount)) {
                               countElement.textContent = currentCount + 1;
                           }
                       }
                       // More robust: fetch the new count, or use WebSockets.
                       // For this example, we just update the button text.
                    }
                } else {
                    // Handle specific errors
                     button.disabled = false; // Re-enable button on error
                     button.textContent = originalText; // Restore original text
                     button.classList.remove('bg-gray-400', 'cursor-not-allowed');
                     // Restore original classes if needed (e.g., blue background)
                     if (originalText === 'Vote Up') {
                         button.classList.add('bg-blue-500', 'hover:bg-blue-600');
                     }

                    if (response.status === 401 || response.status === 403) {
                        // 403 could also be CSRF failure
                        if (result.message && result.message.toLowerCase().includes('token')) {
                             alert(`Security error: ${result.message}. Please refresh and try again.`);
                        } else {
                             alert('Authentication error. Please log in again.');
                             window.location.href = '/login'; // Redirect to login
                        }
                    } else {
                        // General error
                        alert(`Failed to vote: ${result.message || 'Unknown error'}`);
                    }
                     console.error(`Vote failed for story ${storyId}: Status ${response.status}, Message: ${result.message}`);
                }

            } catch (error) {
                console.error('Network error during vote:', error);
                alert('Network error. Could not submit vote.');
                // Re-enable button on network failure
                button.disabled = false;
                button.textContent = originalText;
                button.classList.remove('bg-gray-400', 'cursor-not-allowed');
                 if (originalText === 'Vote Up') {
                    button.classList.add('bg-blue-500', 'hover:bg-blue-600');
                 }
            }
        });
    });
});
