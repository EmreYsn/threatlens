// ── Theme Toggle ──
function initTheme() {
    const saved = localStorage.getItem('threatlens-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    updateToggleIcon(saved);
}

// ──── Theme Toggle ────
function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const newTheme = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);

    // Buton ikonunu güncelle
    const btn = document.querySelector('.theme-toggle');
    if (btn) {
        btn.textContent = newTheme === 'dark' ? '☀' : '🌙';
    }
}

// Sayfa yüklendiğinde tema ayarla
document.addEventListener('DOMContentLoaded', function() {
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    const btn = document.querySelector('.theme-toggle');
    if (btn) {
        btn.textContent = saved === 'dark' ? '☀' : '🌙';
    }
});

function updateToggleIcon(theme) {
    const btn = document.querySelector('.theme-toggle');
    if (btn) btn.textContent = theme === 'dark' ? '☀' : '☾';
}

document.addEventListener('DOMContentLoaded', initTheme);

// ──── Loading Overlay ────
document.addEventListener('DOMContentLoaded', function() {
    // Arama formlarına loading ekle
    const forms = document.querySelectorAll('form[method="post"]');
    forms.forEach(function(form) {
        form.addEventListener('submit', function() {
            const overlay = document.getElementById('loading-overlay');
            if (overlay) {
                overlay.classList.add('active');
            }
        });
    });

    // Mesajları otomatik kapat (5 saniye)
    const messages = document.querySelectorAll('.messages .message');
    messages.forEach(function(msg) {
        // Tıklayınca kapat
        msg.addEventListener('click', function() {
            msg.style.animation = 'slideIn 0.3s ease reverse';
            setTimeout(function() { msg.remove(); }, 300);
        });
        // 5 saniye sonra otomatik kapat
        setTimeout(function() {
            if (msg.parentNode) {
                msg.style.animation = 'slideIn 0.3s ease reverse';
                setTimeout(function() { msg.remove(); }, 300);
            }
        }, 5000);
    });
});