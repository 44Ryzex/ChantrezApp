function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    const notificationText = document.getElementById('notificationText');
    const icon = notification.querySelector('i');
    notificationText.textContent = message;
    icon.className = type === 'success' ? 'fas fa-check-circle' : 'fas fa-exclamation-circle';
    icon.style.color = type === 'success' ? '#3ba55d' : '#ed4245';
    notification.classList.add('show');
    setTimeout(() => notification.classList.remove('show'), 3000);
}
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await response.json();
            if (data.success) {
                showNotification('Login successful!', 'success');
                setTimeout(() => window.location.href = '/dashboard', 1000);
            } else {
                showNotification(data.message, 'error');
            }
        } catch (error) {
            showNotification('Connection error!', 'error');
        }
    });
}
const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const email = document.getElementById('email').value;
        const discordId = document.getElementById('discordId').value;
        const key = document.getElementById('key').value;
        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, email, discordId, key })
            });
            const data = await response.json();
            if (data.success) {
                showNotification('Kayıt başarılı!', 'success');
                setTimeout(() => window.location.href = '/login', 1500);
            } else {
                showNotification(data.message, 'error');
            }
        } catch (error) {
            showNotification('Bağlantı hatası!', 'error');
        }
    });
}
