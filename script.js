document.addEventListener('DOMContentLoaded', function() {
    // Highlight active sidebar link
    const currentPage = window.location.pathname.split('/').pop() || 'home';
    const sidebarLinks = document.querySelectorAll('.sidebar nav ul li a');

    sidebarLinks.forEach(link => {
        if (link.getAttribute('href').includes(currentPage)) {
            link.classList.add('active');
        }
    });

    // Logout button
    const logoutBtn = document.querySelector('.logout-btn');
    logoutBtn.addEventListener('click', function(event) {
        event.preventDefault();
        alert('You have been logged out.');
        window.location.href = '/';
    });

    // Symptom checker hover effects
    const symptomOptions = document.querySelectorAll('.symptom-options label');
    symptomOptions.forEach(option => {
        option.addEventListener('click', () => {
            option.classList.toggle('selected');
        });
    });

    // Theme switching
    const themeSwitch = document.getElementById('theme-switch');
    const body = document.body;

    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    console.log("Saved Theme:", savedTheme); // Debug: Check saved theme
    if (savedTheme) {
        body.setAttribute('data-theme', savedTheme);
        themeSwitch.checked = savedTheme === 'dark';
    }

    // Toggle theme on switch click
    themeSwitch.addEventListener('change', function() {
        console.log("Theme switch clicked!"); // Debug: Check if the switch is working
        if (themeSwitch.checked) {
            body.setAttribute('data-theme', 'dark');
            localStorage.setItem('theme', 'dark');
            console.log("Theme set to Dark Mode");
        } else {
            body.setAttribute('data-theme', 'light');
            localStorage.setItem('theme', 'light');
            console.log("Theme set to Light Mode");
        }
    });
});