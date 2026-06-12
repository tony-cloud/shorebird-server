/**
 * Shorebird Self-Hosted Dashboard — Complete SPA Application
 * Vanilla JS, no framework dependencies.
 */

// ---- State ----
const state = {
    token: localStorage.getItem('shorebird_token') || null,
    user: null,
    apps: [],
    users: [],
    confirmCallback: null,
};

// ---- API Client ----
const api = {
    base: '/api/v1',
    auth: '/auth',

    headers() {
        const h = { 'Content-Type': 'application/json' };
        if (state.token) h['Authorization'] = `Bearer ${state.token}`;
        return h;
    },

    async request(method, path, body) {
        const url = path.startsWith('/auth') ? path : `${this.base}${path}`;
        const opts = { method, headers: this.headers() };
        if (body) opts.body = JSON.stringify(body);
        const res = await fetch(url, opts);
        if (res.status === 204) return null;
        const data = await res.json();
        if (!res.ok) {
            if (res.status === 401) { logout(); throw new Error('Unauthorized'); }
            throw new Error(data.message || 'Request failed');
        }
        return data;
    },

    get(path) { return this.request('GET', path); },
    post(path, body) { return this.request('POST', path, body); },
    patch(path, body) { return this.request('PATCH', path, body); },
    del(path) { return this.request('DELETE', path); },
};

// ---- Navigation ----
function navigate(page) {
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    const section = document.getElementById(`page-${page}`);
    if (section) section.classList.add('active');

    document.querySelectorAll('#sidebarNav a').forEach(a => a.classList.remove('active'));
    const link = document.querySelector(`#sidebarNav a[data-page="${page}"]`);
    if (link) link.classList.add('active');

    const titles = { dashboard: 'Dashboard', apps: 'Apps', users: 'Users', settings: 'Settings' };
    document.getElementById('pageTitle').textContent = titles[page] || page;

    if (page === 'dashboard') loadDashboard();
    if (page === 'apps') loadApps();
    if (page === 'users') loadUsers();
    if (page === 'settings') loadSettings();
}

// ---- Toast Notifications ----
function showToast(message, type) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 4000);
}

// ---- Modals ----
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

function confirmAction(title, message, callback) {
    document.getElementById('confirmTitle').textContent = title;
    document.getElementById('confirmMessage').textContent = message;
    state.confirmCallback = callback;
    openModal('confirmModal');
}
function executeConfirm() {
    if (state.confirmCallback) state.confirmCallback();
    closeModal('confirmModal');
}

// ---- Auth ----
async function login(email, password) {
    const data = await api.request('POST', '/auth/token', { email, password });
    state.token = data.token;
    localStorage.setItem('shorebird_token', data.token);
    await loadCurrentUser();
    showApp();
    navigate('dashboard');
}

function logout() {
    state.token = null;
    state.user = null;
    state.apps = [];
    localStorage.removeItem('shorebird_token');
    document.getElementById('appContainer').classList.remove('active');
    document.getElementById('loginPage').style.display = 'flex';
}

async function loadCurrentUser() {
    try {
        state.user = await api.get('/users/me');
        document.getElementById('currentUserEmail').textContent = state.user.email || '—';
    } catch (e) {
        // User endpoint might not be available
        state.user = { email: 'admin' };
    }
}

function showApp() {
    document.getElementById('loginPage').style.display = 'none';
    document.getElementById('appContainer').classList.add('active');
}

async function register(name, email, password) {
    const data = await api.request('POST', '/auth/register', { name, email, password });
    state.token = data.token;
    localStorage.setItem('shorebird_token', data.token);
    await loadCurrentUser();
    closeModal('registerOverlay');
    showApp();
    navigate('dashboard');
    showToast('Account created successfully', 'success');
}

// ---- Dashboard ----
async function loadDashboard() {
    try {
        const appsResp = await api.get('/apps');
        state.apps = appsResp.apps || [];
        document.getElementById('statApps').textContent = state.apps.length;
        document.getElementById('statPatches').textContent = '—';

        // Try to get users
        try {
            const usersResp = await api.get('/admin/users');
            state.users = usersResp.users || [];
            document.getElementById('statUsers').textContent = state.users.length;
        } catch {
            document.getElementById('statUsers').textContent = '—';
        }

        // Try to get organizations
        try {
            const orgsResp = await api.get('/organizations');
            const orgs = orgsResp.organizations || [];
            document.getElementById('statOrganizations').textContent = orgs.length;
        } catch {
            document.getElementById('statOrganizations').textContent = '—';
        }

        // Recent apps table
        const tableDiv = document.getElementById('recentAppsTable');
        if (state.apps.length === 0) {
            tableDiv.innerHTML = '<div class="empty-state"><div class="empty-icon">📱</div><p>No apps yet. Create your first app to get started.</p></div>';
        } else {
            const recent = state.apps.slice(0, 5);
            tableDiv.innerHTML = renderTable(
                ['App Name', 'App ID', 'Created'],
                recent.map(a => [
                    a.display_name,
                    `<code class="code">${a.app_id}</code>`,
                    new Date(a.created_at).toLocaleDateString(),
                ])
            );
        }
    } catch (e) {
        showToast('Failed to load dashboard', 'error');
    }
}

// ---- Apps ----
async function loadApps() {
    try {
        const resp = await api.get('/apps');
        state.apps = resp.apps || [];
        const tableDiv = document.getElementById('appsTable');

        if (state.apps.length === 0) {
            tableDiv.innerHTML = '<div class="empty-state"><div class="empty-icon">📱</div><p>No apps yet. Create your first app.</p></div>';
            return;
        }

        tableDiv.innerHTML = renderTable(
            ['App Name', 'App ID', 'Created', 'Actions'],
            state.apps.map(a => [
                a.display_name,
                `<code class="code">${a.app_id}</code>`,
                new Date(a.created_at).toLocaleDateString(),
                `<button class="btn btn-ghost" onclick="copyToClipboard('${a.app_id}')" title="Copy App ID">📋</button>
                 <button class="btn btn-ghost" onclick="confirmDeleteApp('${a.app_id}','${escapeHtml(a.display_name)}')" title="Delete App">🗑️</button>`,
            ])
        );
    } catch (e) {
        showToast('Failed to load apps', 'error');
    }
}

async function createApp(displayName) {
    try {
        await api.post('/apps', { display_name: displayName, organization_id: 0 });
        closeModal('createAppOverlay');
        showToast(`App "${displayName}" created`, 'success');
        loadApps();
        loadDashboard();
    } catch (e) {
        showToast(e.message || 'Failed to create app', 'error');
    }
}

function confirmDeleteApp(appId, name) {
    confirmAction('Delete App', `Are you sure you want to delete "${name}"? This action cannot be undone.`, async () => {
        try {
            await api.del(`/apps/${appId}`);
            showToast(`App "${name}" deleted`, 'success');
            loadApps();
            loadDashboard();
        } catch (e) {
            showToast(e.message || 'Failed to delete app', 'error');
        }
    });
}

function openCreateAppModal() {
    document.getElementById('appDisplayName').value = '';
    openModal('createAppOverlay');
}

// ---- Users ----
async function loadUsers() {
    try {
        const resp = await api.get('/admin/users');
        state.users = resp.users || [];
        const tableDiv = document.getElementById('usersTable');

        if (state.users.length === 0) {
            tableDiv.innerHTML = '<div class="empty-state"><div class="empty-icon">👥</div><p>No users found.</p></div>';
            return;
        }

        tableDiv.innerHTML = renderTable(
            ['ID', 'Email', 'Name', 'Role', 'Created'],
            state.users.map(u => [
                u.id,
                u.email,
                u.name || '—',
                u.role ? `<span class="badge badge-info">${u.role}</span>` : `<span class="badge">member</span>`,
                u.created_at ? new Date(u.created_at).toLocaleDateString() : '—',
            ])
        );
    } catch (e) {
        // If admin/users endpoint is not available, show a message
        document.getElementById('usersTable').innerHTML =
            '<div class="empty-state"><div class="empty-icon">👥</div><p>User management API not available. Check server configuration.</p></div>';
    }
}

async function createUser(name, email, password) {
    try {
        await api.request('POST', '/auth/register', { name, email, password });
        closeModal('createUserOverlay');
        showToast(`User "${email}" created`, 'success');
        loadUsers();
    } catch (e) {
        showToast(e.message || 'Failed to create user', 'error');
    }
}

function openCreateUserModal() {
    document.getElementById('newUserName').value = '';
    document.getElementById('newUserEmail').value = '';
    document.getElementById('newUserPassword').value = '';
    openModal('createUserOverlay');
}

// ---- Settings ----
async function loadSettings() {
    // Try to get server info from health endpoint
    let backendInfo = { storage: 'Unknown', database: 'Unknown' };
    try {
        const resp = await fetch('/health');
        const data = await resp.json();
        if (data.backend) backendInfo = data.backend;
    } catch (e) { /* use defaults */ }

    const infoDiv = document.getElementById('serverInfo');
    infoDiv.innerHTML = `
        <div class="info-item">
            <div class="info-label">Server Version</div>
            <div class="info-value">Shorebird Self-Hosted v1.0</div>
        </div>
        <div class="info-item">
            <div class="info-label">API Base URL</div>
            <div class="info-value"><code class="code">${window.location.origin}/api/v1</code></div>
        </div>
        <div class="info-item">
            <div class="info-label">Auth Endpoint</div>
            <div class="info-value"><code class="code">${window.location.origin}/auth</code></div>
        </div>
        <div class="info-item">
            <div class="info-label">Storage Backend</div>
            <div class="info-value"><span class="badge badge-info">${backendInfo.storage}</span></div>
        </div>
        <div class="info-item">
            <div class="info-label">Database Backend</div>
            <div class="info-value"><span class="badge badge-success">${backendInfo.database}</span></div>
        </div>
        <div class="info-item">
            <div class="info-label">UI Version</div>
            <div class="info-value">1.0.0</div>
        </div>
    `;

    document.getElementById('apiTokenDisplay').value = state.token || 'Not authenticated';
}

// ---- Helpers ----
function renderTable(headers, rows) {
    let html = '<table><thead><tr>';
    headers.forEach(h => { html += `<th>${h}</th>`; });
    html += '</tr></thead><tbody>';
    rows.forEach(row => {
        html += '<tr>';
        row.forEach(cell => { html += `<td>${cell}</td>`; });
        html += '</tr>';
    });
    html += '</tbody></table>';
    return html;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard', 'success');
    }).catch(() => {
        // Fallback
        const input = document.createElement('input');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showToast('Copied to clipboard', 'success');
    });
}

// ---- Event Listeners ----
document.addEventListener('DOMContentLoaded', () => {
    // Login form
    document.getElementById('loginForm').addEventListener('submit', async e => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        const errorDiv = document.getElementById('loginError');
        errorDiv.style.display = 'none';
        try {
            await login(email, password);
        } catch (err) {
            errorDiv.textContent = err.message || 'Login failed. Check your credentials.';
            errorDiv.style.display = 'block';
        }
    });

    // Register form (modal)
    document.getElementById('registerForm').addEventListener('submit', async e => {
        e.preventDefault();
        const name = document.getElementById('regName').value;
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPassword').value;
        try {
            await register(name, email, password);
        } catch (err) {
            showToast(err.message || 'Registration failed', 'error');
        }
    });

    // Show register modal
    document.getElementById('showRegister').addEventListener('click', e => {
        e.preventDefault();
        document.getElementById('regName').value = '';
        document.getElementById('regEmail').value = '';
        document.getElementById('regPassword').value = '';
        openModal('registerOverlay');
    });

    function closeRegister() { closeModal('registerOverlay'); }
    window.closeRegister = closeRegister;

    // Create app form
    document.getElementById('createAppForm').addEventListener('submit', async e => {
        e.preventDefault();
        const name = document.getElementById('appDisplayName').value;
        await createApp(name);
    });

    // Create user form
    document.getElementById('createUserForm').addEventListener('submit', async e => {
        e.preventDefault();
        const name = document.getElementById('newUserName').value;
        const email = document.getElementById('newUserEmail').value;
        const password = document.getElementById('newUserPassword').value;
        await createUser(name, email, password);
    });

    // Sidebar navigation
    document.querySelectorAll('#sidebarNav a').forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            const page = link.dataset.page;
            navigate(page);
            window.location.hash = page;
        });
    });

    // Logout
    document.getElementById('logoutBtn').addEventListener('click', () => {
        logout();
        window.location.hash = '';
    });

    // Close modals on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', e => {
            if (e.target === overlay) closeModal(overlay.id);
        });
    });

    // Auto-login if token exists
    if (state.token) {
        loadCurrentUser().then(() => {
            showApp();
            const page = window.location.hash.replace('#', '') || 'dashboard';
            navigate(page);
        }).catch(() => {
            logout();
        });
    }
});

// Export functions for inline onclick handlers
window.openCreateAppModal = openCreateAppModal;
window.openCreateUserModal = openCreateUserModal;
window.confirmDeleteApp = confirmDeleteApp;
window.copyToClipboard = copyToClipboard;
window.closeModal = closeModal;
