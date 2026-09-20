// PhishShield Dashboard - VirusTotal Style

document.addEventListener('DOMContentLoaded', function() {
    console.log('PhishShield Dashboard ready');

    // ===== Tab Switching =====
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            tabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            showNotification(`Switched to: ${this.textContent.trim()}`);
        });
    });

    // ===== Quick Actions =====
    const actionBtns = document.querySelectorAll('.action-btn');
    actionBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const action = this.textContent.trim();
            showNotification(`Action: ${action}`);
        });
    });

    // ===== Refresh Button =====
    const refreshBtn = document.querySelector('.footer-right button:first-child');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            showNotification('Refreshing dashboard...');
            setTimeout(() => showNotification('Dashboard refreshed'), 1000);
        });
    }

    // ===== Generate Report =====
    const reportBtn = document.querySelector('.footer-right .btn-primary');
    if (reportBtn) {
        reportBtn.addEventListener('click', function() {
            showNotification('Generating report...');
            setTimeout(() => showNotification('Report ready for download'), 2000);
        });
    }

    // ===== Reanalyze =====
    const reanalyzeBtn = document.querySelector('.action-links span:first-child');
    if (reanalyzeBtn) {
        reanalyzeBtn.addEventListener('click', function() {
            showNotification('Reanalyzing all URLs...');
            setTimeout(() => showNotification('Analysis complete'), 1500);
        });
    }

    // ===== Filter Buttons =====
    const filterBtns = document.querySelectorAll('.filter-btns button');
    filterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            if (this.disabled) return;
            filterBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            showNotification(`Filter: ${this.textContent}`);
        });
    });

    // ===== Search =====
    const searchInput = document.querySelector('.vendor-toolbar input');
    if (searchInput) {
        searchInput.addEventListener('keyup', function(e) {
            if (e.key === 'Enter' && this.value.trim()) {
                showNotification(`Searching: ${this.value.trim()}`);
            }
        });
    }

    // ===== Notification System =====
    function showNotification(message, type = 'info') {
        const existing = document.querySelector('.notification-toast');
        if (existing) existing.remove();

        const colors = {
            info: '#4b7cf7',
            success: '#6fcf97',
            warning: '#f0b34b',
            error: '#f2635c'
        };
        const icons = {
            info: 'fa-info-circle',
            success: 'fa-check-circle',
            warning: 'fa-exclamation-triangle',
            error: 'fa-times-circle'
        };

        const toast = document.createElement('div');
        toast.className = 'notification-toast';
        toast.innerHTML = `
            <i class="fas ${icons[type]}" style="color: ${colors[type]};"></i>
            <span>${message}</span>
        `;
        toast.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: #1a2332;
            border: 1px solid ${colors[type]}44;
            border-radius: 12px;
            padding: 14px 24px;
            color: #e8edf5;
            font-size: 14px;
            z-index: 1000;
            display: flex;
            align-items: center;
            gap: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.6);
            animation: slideUp 0.3s ease;
            max-width: 420px;
        `;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideDown 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    }

    // ===== Keyboard Shortcuts =====
    document.addEventListener('keydown', function(e) {
        // Ctrl+Shift+N = New Scan
        if (e.ctrlKey && e.shiftKey && e.key === 'N') {
            e.preventDefault();
            document.querySelector('.action-btn.primary')?.click();
        }
        // Ctrl+Shift+R = Refresh
        if (e.ctrlKey && e.shiftKey && e.key === 'R') {
            e.preventDefault();
            refreshBtn?.click();
        }
    });

    console.log('Keyboard shortcuts:');
    console.log('  Ctrl+Shift+N = New Scan');
    console.log('  Ctrl+Shift+R = Refresh');

    // ===== Animations =====
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideUp {
            from { transform: translateY(40px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        @keyframes slideDown {
            from { transform: translateY(0); opacity: 1; }
            to { transform: translateY(40px); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
});