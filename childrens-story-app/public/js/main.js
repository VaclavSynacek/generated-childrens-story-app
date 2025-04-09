// Add basic client-side validation feedback if needed
document.addEventListener('DOMContentLoaded', () => {
  // Example: Password match validation on registration form
  const registerForm = document.getElementById('register-form'); // Add id="register-form" to your form
  if (registerForm) {
    const password = registerForm.querySelector('#password');
    const confirmPassword = registerForm.querySelector('#confirmPassword');
    const confirmPasswordError = document.getElementById('confirmPasswordError'); // Add <p id="confirmPasswordError" class="text-red-500 text-xs italic mt-1"></p>

    const validatePasswordMatch = () => {
      if (!password || !confirmPassword) return; // Elements might not exist

      if (password.value && confirmPassword.value && password.value !== confirmPassword.value) {
        confirmPassword.classList.add('border-red-500');
        if(confirmPasswordError) confirmPasswordError.textContent = 'Passwords do not match.';
      } else {
        confirmPassword.classList.remove('border-red-500');
         if(confirmPasswordError) confirmPasswordError.textContent = '';
      }
    };

    if (password && confirmPassword) {
        password.addEventListener('input', validatePasswordMatch);
        confirmPassword.addEventListener('input', validatePasswordMatch);
    }
  }

  // Add more client-side validation as needed (e.g., required fields)
  // Note: Server-side validation is the source of truth.

  // Simple dismiss for flash messages
  const closeButtons = document.querySelectorAll('[role="alert"] button');
  closeButtons.forEach(button => {
      button.addEventListener('click', (e) => {
          e.target.closest('[role="alert"]').remove();
      });
  });

});
