/**
 * Shorebird Self-Hosted Dashboard - Complete SPA Application
 * Vanilla JS, no framework dependencies.
 */

// ---- State ----
const state = {
    token: localStorage.getItem('shorebird_token') || null,
    user: null,
    apps: [],
    users: [],
    organizations: [],
    currentApp: null,
    currentRelease: null,
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

    const titles = { dashboard: 'Dashboard', apps: 'Apps', users: 'Users', organizations: 'Organizations', settings: 'Settings' };
    document.getElementById('pageTitle').textContent = titles[page] || page;

    if (page === 'dashboard') loadDashboard();
    if (page === 'apps') loadApps();
    if (page === 'users') loadUsers();
    if (page === 'organizations') loadOrganizations();
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
    state.mustChangePassword = data.must_change_password;
    localStorage.setItem('shorebird_token', data.token);
    await loadCurrentUser();
    showApp();
    if (state.mustChangePassword || state.user.must_change_password) {
        navigate('settings');
        openModal('forcePasswordOverlay');
    } else {
        navigate('dashboard');
    }
}

async function loadPublicSettings() {
    try {
        const data = await api.request('GET', '/auth/public-settings');
        document.getElementById('ssoLoginBtn').style.display = data.sso_enabled ? 'inline-flex' : 'none';
        const canRegister = data.registration_enabled && !data.sso_only_registration;
        document.getElementById('registerPrompt').style.display = canRegister ? 'inline' : 'none';
    } catch {
        document.getElementById('ssoLoginBtn').style.display = 'none';
    }
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
        document.getElementById('currentUserEmail').textContent = state.user.email || '-';
        if (state.user.must_change_password) setTimeout(() => openModal('forcePasswordOverlay'), 0);
    } catch (e) {
        state.user = { email: 'admin' };
    }
}

function showApp() {
    document.getElementById('loginPage').style.display = 'none';
    document.getElementById('appContainer').classList.add('active');
}

async function register(name, email, password) {
    await api.request('POST', '/auth/register', { name, email, password });
    closeModal('registerOverlay');
    showToast('Account created. Check your email to verify before signing in.', 'success');
}

// ---- Dashboard ----
async function loadDashboard() {
    try {
        const appsResp = await api.get('/apps');
        state.apps = appsResp.apps || [];
        document.getElementById('statApps').textContent = state.apps.length;
        document.getElementById('statPatches').textContent = '-';

        // Try to get users
        try {
            const usersResp = await api.get('/admin/users');
            state.users = usersResp.users || [];
            document.getElementById('statUsers').textContent = state.users.length;
        } catch {
            document.getElementById('statUsers').textContent = '-';
        }

        // Try to get organizations
        try {
            const orgsResp = await api.get('/organizations');
            const orgs = orgsResp.organizations || [];
            document.getElementById('statOrganizations').textContent = orgs.length;
        } catch {
            document.getElementById('statOrganizations').textContent = '-';
        }

        // Recent apps table
        const tableDiv = document.getElementById('recentAppsTable');
        if (state.apps.length === 0) {
            tableDiv.innerHTML = '<div class="empty-state"><div class="empty-icon">Apps</div><p>No apps yet. Create your first app to get started.</p></div>';
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
            tableDiv.innerHTML = '<div class="empty-state"><div class="empty-icon">Apps</div><p>No apps yet. Create your first app.</p></div>';
            return;
        }

        tableDiv.innerHTML = renderTable(
            ['App Name', 'App ID', 'Created', 'Actions'],
            state.apps.map(a => [
                a.display_name,
                `<code class="code">${a.app_id}</code>`,
                new Date(a.created_at).toLocaleDateString(),
                `<button class="btn btn-ghost" onclick="copyToClipboard('${a.app_id}')" title="Copy App ID">Copy</button>
                 <button class="btn btn-ghost" onclick="confirmDeleteApp('${a.app_id}','${escapeHtml(a.display_name)}')" title="Delete App">Delete</button>`,
            ])
        );
    } catch (e) {
        showToast('Failed to load apps', 'error');
    }
}

async function createApp(displayName, organizationId) {
    try {
        await api.post('/apps', { display_name: displayName, organization_id: Number(organizationId || 0) });
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
    const select = document.getElementById('appOrganizationId');
    select.innerHTML = '<option value="0">Default organization</option>';
    api.get('/organizations').then(resp => {
        state.organizations = resp.organizations || [];
        if (state.organizations.length > 0) {
            select.innerHTML = state.organizations
                .map(m => `<option value="${m.organization.id}">${escapeHtml(m.organization.name)}</option>`)
                .join('');
        }
    }).catch(() => {});
    openModal('createAppOverlay');
}

// ---- Users ----
async function loadUsers() {
    try {
        const resp = await api.get('/admin/users');
        state.users = resp.users || [];
        const tableDiv = document.getElementById('usersTable');

        if (state.users.length === 0) {
            tableDiv.innerHTML = '<div class="empty-state"><div class="empty-icon">Users</div><p>No users found.</p></div>';
            return;
        }

        tableDiv.innerHTML = renderTable(
            ['ID', 'Email', 'Name', 'Role', 'Created'],
            state.users.map(u => [
                u.id,
                u.email,
                u.name || '-',
                u.role ? `<span class="badge badge-info">${u.role}</span>` : `<span class="badge">member</span>`,
                u.created_at ? new Date(u.created_at).toLocaleDateString() : '-',
            ])
        );
    } catch (e) {
        // If admin/users endpoint is not available, show a message
        document.getElementById('usersTable').innerHTML =
            '<div class="empty-state"><div class="empty-icon">Users</div><p>User management API not available. Check server configuration.</p></div>';
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

// ---- Admin Users ----
async function loadUsers() {
    try {
        const resp = await api.get('/admin/users');
        state.users = resp.users || [];
        const tableDiv = document.getElementById('usersTable');
        if (state.users.length === 0) {
            tableDiv.innerHTML = '<div class="empty-state"><p>No users found.</p></div>';
            return;
        }
        tableDiv.innerHTML = renderTable(
            ['ID', 'Email', 'Name', 'Role', 'Verified', 'Admin', 'Actions'],
            state.users.map(u => [
                u.id,
                escapeHtml(u.email),
                escapeHtml(u.name || '-'),
                u.role ? `<span class="badge badge-info">${escapeHtml(u.role)}</span>` : '<span class="badge">member</span>',
                u.email_verified ? '<span class="badge badge-success">verified</span>' : '<span class="badge badge-warning">pending</span>',
                u.is_admin ? '<span class="badge badge-success">admin</span>' : '<span class="badge">user</span>',
                `<button class="btn btn-ghost" onclick="verifyUserEmail(${u.id})">Verify</button>
                 <button class="btn btn-ghost" onclick="setUserAdmin(${u.id}, ${!u.is_admin})">${u.is_admin ? 'Revoke admin' : 'Make admin'}</button>`,
            ])
        );
    } catch {
        document.getElementById('usersTable').innerHTML =
            '<div class="empty-state"><p>Admin access required for user management.</p></div>';
    }
}

async function verifyUserEmail(userId) {
    try {
        await api.post(`/admin/users/${userId}/verify-email`, {});
        showToast('User email verified', 'success');
        loadUsers();
    } catch (e) {
        showToast(e.message || 'Failed to verify email', 'error');
    }
}

async function setUserAdmin(userId, isAdmin) {
    try {
        await api.post(`/admin/users/${userId}/admin`, { is_admin: isAdmin });
        showToast('Admin status updated', 'success');
        loadUsers();
    } catch (e) {
        showToast(e.message || 'Failed to update admin status', 'error');
    }
}

// ---- Organizations ----
async function loadOrganizations() {
    try {
        const resp = await api.get('/organizations');
        state.organizations = resp.organizations || [];
        const tableDiv = document.getElementById('organizationsTable');
        if (state.organizations.length === 0) {
            tableDiv.innerHTML = '<div class="empty-state"><p>No organizations found.</p></div>';
            document.getElementById('organizationMembersTable').innerHTML = '';
            return;
        }
        tableDiv.innerHTML = renderTable(
            ['ID', 'Name', 'Type', 'Your Role', 'Actions'],
            state.organizations.map(m => [
                m.organization.id,
                escapeHtml(m.organization.name),
                escapeHtml(m.organization.organization_type),
                `<span class="badge badge-info">${escapeHtml(m.role)}</span>`,
                `<button class="btn btn-ghost" onclick="loadOrganizationMembers(${m.organization.id})">Members</button>
                 <button class="btn btn-ghost" onclick="openAddOrgUserModal(${m.organization.id})">Add user</button>`,
            ])
        );
        loadOrganizationMembers(state.organizations[0].organization.id);
    } catch {
        document.getElementById('organizationsTable').innerHTML =
            '<div class="empty-state"><p>Failed to load organizations.</p></div>';
    }
}

async function loadOrganizationMembers(orgId) {
    try {
        const resp = await api.get(`/organizations/${orgId}/users`);
        const users = resp.users || [];
        document.getElementById('organizationMembersTable').innerHTML = renderTable(
            ['Email', 'Name', 'Role', 'Verified', 'Admin'],
            users.map(u => [
                escapeHtml(u.email),
                escapeHtml(u.name || '-'),
                `<span class="badge badge-info">${escapeHtml(u.role)}</span>`,
                u.email_verified ? '<span class="badge badge-success">verified</span>' : '<span class="badge badge-warning">pending</span>',
                u.is_admin ? '<span class="badge badge-success">admin</span>' : '<span class="badge">user</span>',
            ])
        );
    } catch {
        document.getElementById('organizationMembersTable').innerHTML =
            '<div class="empty-state"><p>Organization admin access required to view members.</p></div>';
    }
}

async function createOrganization(name) {
    try {
        await api.post('/organizations', { name, organization_type: 'team' });
        closeModal('createOrgOverlay');
        showToast('Organization created', 'success');
        loadOrganizations();
    } catch (e) {
        showToast(e.message || 'Failed to create organization', 'error');
    }
}

function openCreateOrgModal() {
    document.getElementById('orgName').value = '';
    openModal('createOrgOverlay');
}

function openAddOrgUserModal(orgId) {
    document.getElementById('orgUserOrgId').value = orgId;
    document.getElementById('orgUserEmail').value = '';
    document.getElementById('orgUserRole').value = 'member';
    openModal('addOrgUserOverlay');
}

async function addOrganizationUser(orgId, email, role) {
    try {
        await api.post(`/organizations/${orgId}/users`, { email, role });
        closeModal('addOrgUserOverlay');
        showToast('User added to organization', 'success');
        loadOrganizationMembers(orgId);
    } catch (e) {
        showToast(e.message || 'Failed to add user', 'error');
    }
}

// ---- Settings override ----
async function loadSettings() {
    let backendInfo = { storage: 'Unknown', database: 'Unknown' };
    try {
        const resp = await fetch('/health');
        const data = await resp.json();
        if (data.backend) backendInfo = data.backend;
    } catch {}

    document.getElementById('serverInfo').innerHTML = `
        <div class="info-item"><div class="info-label">Server Version</div><div class="info-value">Shorebird Self-Hosted v1.0</div></div>
        <div class="info-item"><div class="info-label">API Base URL</div><div class="info-value"><code class="code">${window.location.origin}/api/v1</code></div></div>
        <div class="info-item"><div class="info-label">Auth Endpoint</div><div class="info-value"><code class="code">${window.location.origin}/auth</code></div></div>
        <div class="info-item"><div class="info-label">Storage Backend</div><div class="info-value"><span class="badge badge-info">${backendInfo.storage}</span></div></div>
        <div class="info-item"><div class="info-label">Database Backend</div><div class="info-value"><span class="badge badge-success">${backendInfo.database}</span></div></div>
        <div class="info-item"><div class="info-label">Current User</div><div class="info-value">${escapeHtml(state.user?.email || '-')}</div></div>
    `;
    document.getElementById('apiTokenDisplay').value = state.token || 'Not authenticated';

    try {
        const resp = await api.get('/admin/settings');
        const settings = resp.settings || {};
        document.getElementById('settingRegistrationEnabled').checked = settings.registration_enabled === 'true';
        document.getElementById('settingSsoRegistrationEnabled').checked = settings.sso_registration_enabled === 'true';
        document.getElementById('settingSsoOnlyRegistration').checked = settings.sso_only_registration === 'true';
        document.getElementById('casdoorEndpoint').value = settings.casdoor_endpoint || '';
        document.getElementById('casdoorClientId').value = settings.casdoor_client_id || '';
        document.getElementById('casdoorClientSecret').value = '';
        document.getElementById('casdoorOrganization').value = settings.casdoor_organization || 'built-in';
    } catch {
        document.getElementById('adminSettingsForm').innerHTML = '<p style="color:var(--text-muted);font-size:14px;">Admin access required for server settings.</p>';
    }
}

// ---- Event Listeners ----
document.addEventListener('DOMContentLoaded', () => {
    loadPublicSettings();

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

    document.getElementById('showPasswordReset').addEventListener('click', e => {
        e.preventDefault();
        document.getElementById('resetEmail').value = document.getElementById('loginEmail').value || '';
        openModal('passwordResetOverlay');
    });

    function closeRegister() { closeModal('registerOverlay'); }
    window.closeRegister = closeRegister;

    // Create app form
    document.getElementById('createAppForm').addEventListener('submit', async e => {
        e.preventDefault();
        const name = document.getElementById('appDisplayName').value;
        const orgId = document.getElementById('appOrganizationId').value;
        await createApp(name, orgId);
    });

    // Create user form
    document.getElementById('createUserForm').addEventListener('submit', async e => {
        e.preventDefault();
        const name = document.getElementById('newUserName').value;
        const email = document.getElementById('newUserEmail').value;
        const password = document.getElementById('newUserPassword').value;
        await createUser(name, email, password);
    });

    document.getElementById('passwordResetForm').addEventListener('submit', async e => {
        e.preventDefault();
        const email = document.getElementById('resetEmail').value;
        try {
            await api.request('POST', '/auth/password-reset/request', { email });
            closeModal('passwordResetOverlay');
            showToast('Password reset email sent if the account exists', 'success');
        } catch (err) {
            showToast(err.message || 'Failed to request reset', 'error');
        }
    });

    document.getElementById('changePasswordForm').addEventListener('submit', async e => {
        e.preventDefault();
        try {
            await api.patch('/users/me/password', {
                current_password: document.getElementById('currentPassword').value,
                new_password: document.getElementById('newPassword').value,
            });
            document.getElementById('changePasswordForm').reset();
            showToast('Password changed', 'success');
        } catch (err) {
            showToast(err.message || 'Failed to change password', 'error');
        }
    });

    document.getElementById('forcePasswordForm').addEventListener('submit', async e => {
        e.preventDefault();
        try {
            await api.patch('/users/me/password', {
                current_password: '',
                new_password: document.getElementById('forceNewPassword').value,
            });
            state.mustChangePassword = false;
            if (state.user) state.user.must_change_password = false;
            closeModal('forcePasswordOverlay');
            document.getElementById('forcePasswordForm').reset();
            showToast('Password updated', 'success');
            navigate('dashboard');
        } catch (err) {
            showToast(err.message || 'Failed to update password', 'error');
        }
    });

    document.getElementById('adminSettingsForm').addEventListener('submit', async e => {
        e.preventDefault();
        const body = {
            registration_enabled: String(document.getElementById('settingRegistrationEnabled').checked),
            sso_registration_enabled: String(document.getElementById('settingSsoRegistrationEnabled').checked),
            sso_only_registration: String(document.getElementById('settingSsoOnlyRegistration').checked),
            casdoor_endpoint: document.getElementById('casdoorEndpoint').value,
            casdoor_client_id: document.getElementById('casdoorClientId').value,
            casdoor_client_secret: document.getElementById('casdoorClientSecret').value,
            casdoor_organization: document.getElementById('casdoorOrganization').value,
        };
        try {
            await api.request('PUT', '/admin/settings', body);
            showToast('Settings saved', 'success');
            loadPublicSettings();
            loadSettings();
        } catch (err) {
            showToast(err.message || 'Failed to save settings', 'error');
        }
    });

    document.getElementById('createOrgForm').addEventListener('submit', async e => {
        e.preventDefault();
        await createOrganization(document.getElementById('orgName').value);
    });

    document.getElementById('addOrgUserForm').addEventListener('submit', async e => {
        e.preventDefault();
        await addOrganizationUser(
            document.getElementById('orgUserOrgId').value,
            document.getElementById('orgUserEmail').value,
            document.getElementById('orgUserRole').value,
        );
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
            if (state.user.must_change_password) {
                navigate('settings');
                openModal('forcePasswordOverlay');
            } else {
                const page = window.location.hash.replace('#', '') || 'dashboard';
                navigate(page);
            }
        }).catch(() => {
            logout();
        });
    }
});

// ---- App Detail Views ----
function setActivePage(page) {
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    const section = document.getElementById(`page-${page}`);
    if (section) section.classList.add('active');
}

function platformBadges(statuses) {
    const entries = Object.entries(statuses || {});
    if (entries.length === 0) return '<span class="badge">no platforms</span>';
    return entries.map(([platform, status]) => `<span class="badge badge-info" title="${escapeHtml(status)}">${escapeHtml(platform)}</span>`).join(' ');
}

function humanSize(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
    return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

async function loadApps() {
    try {
        const resp = await api.get('/apps');
        state.apps = resp.apps || [];
        const tableDiv = document.getElementById('appsTable');
        if (state.apps.length === 0) {
            tableDiv.innerHTML = '<div class="empty-state"><p>No apps yet. Create your first app.</p></div>';
            return;
        }
        tableDiv.innerHTML = renderTable(
            ['App Name', 'App ID', 'Created', 'Actions'],
            state.apps.map(a => [
                `<button class="btn btn-ghost" onclick="openAppPage('${a.app_id}')">${escapeHtml(a.display_name)}</button>`,
                `<code class="code">${a.app_id}</code>`,
                new Date(a.created_at).toLocaleDateString(),
                `<button class="btn btn-ghost" onclick="openAppPage('${a.app_id}')">Open</button>
                 <button class="btn btn-ghost" onclick="copyToClipboard('${a.app_id}')">Copy</button>`,
            ])
        );
    } catch {
        showToast('Failed to load apps', 'error');
    }
}

async function openAppPage(appId) {
    const app = state.apps.find(a => a.app_id === appId) || { app_id: appId, display_name: appId };
    state.currentApp = app;
    setActivePage('app-detail');
    document.getElementById('pageTitle').textContent = app.display_name;
    document.getElementById('appDetailTitle').textContent = app.display_name;
    showAppTab('releases');
}

async function showAppTab(tab) {
    document.querySelectorAll('[data-app-tab]').forEach(b => b.classList.toggle('active', b.dataset.appTab === tab));
    document.querySelectorAll('.app-tab').forEach(el => { el.style.display = el.id === `appTab-${tab}` ? 'block' : 'none'; });
    if (!state.currentApp) return;
    if (tab === 'releases') await renderAppReleases();
    if (tab === 'insights') await renderAppInsights();
    if (tab === 'collaborators') await renderAppCollaborators();
    if (tab === 'tracks') await renderAppTracks();
    if (tab === 'settings') await renderAppSettings();
}

async function renderAppReleases() {
    const div = document.getElementById('appTab-releases');
    const resp = await api.get(`/apps/${state.currentApp.app_id}/releases`);
    state.currentApp.releases = resp.releases || [];
    if (state.currentApp.releases.length === 0) {
        div.innerHTML = '<div class="empty-state"><p>No releases yet.</p></div>';
        return;
    }
    div.innerHTML = renderTable(
        ['Version', 'Platforms', 'Flutter', 'Created', 'Actions'],
        state.currentApp.releases.map(r => [
            `<button class="btn btn-ghost" onclick="openReleasePage(${r.id})">${escapeHtml(r.version)}</button>`,
            platformBadges(r.platform_statuses),
            escapeHtml(r.flutter_version || r.flutter_revision || '-'),
            new Date(r.created_at).toLocaleDateString(),
            `<button class="btn btn-ghost" onclick="openReleasePage(${r.id})">Open</button>`,
        ])
    );
}

async function renderAppInsights() {
    const releases = state.currentApp.releases || (await api.get(`/apps/${state.currentApp.app_id}/releases`)).releases || [];
    document.getElementById('appTab-insights').innerHTML = `
        <div class="stats-grid">
            <div class="stat-card primary"><div class="stat-value">${releases.length}</div><div class="stat-label">Releases</div></div>
            <div class="stat-card success"><div class="stat-value">${new Set(releases.flatMap(r => Object.keys(r.platform_statuses || {}))).size}</div><div class="stat-label">Platforms</div></div>
            <div class="stat-card warning"><div class="stat-value">0</div><div class="stat-label">Downloads tracked</div></div>
        </div>
        <p class="form-hint">Download metrics are shown when artifact/download events are recorded.</p>`;
}

async function renderAppCollaborators() {
    const orgs = await api.get('/organizations');
    const membership = (orgs.organizations || []).find(m => m.organization.id === state.currentApp.organization_id);
    if (!membership) {
        document.getElementById('appTab-collaborators').innerHTML = '<div class="empty-state"><p>No organization membership found.</p></div>';
        return;
    }
    try {
        const resp = await api.get(`/organizations/${membership.organization.id}/users`);
        document.getElementById('appTab-collaborators').innerHTML = renderTable(
            ['Email', 'Name', 'Role'],
            (resp.users || []).map(u => [escapeHtml(u.email), escapeHtml(u.name || '-'), `<span class="badge badge-info">${escapeHtml(u.role)}</span>`])
        );
    } catch {
        document.getElementById('appTab-collaborators').innerHTML = '<div class="empty-state"><p>Organization admin access required.</p></div>';
    }
}

async function renderAppTracks() {
    try {
        const channels = await api.get(`/apps/${state.currentApp.app_id}/channels`);
        document.getElementById('appTab-tracks').innerHTML = renderTable(
            ['Track', 'ID'],
            (channels || []).map(c => [escapeHtml(c.name), c.id])
        );
    } catch {
        document.getElementById('appTab-tracks').innerHTML = '<div class="empty-state"><p>No tracks found.</p></div>';
    }
}

async function renderAppSettings() {
    const orgs = await api.get('/organizations').catch(() => ({ organizations: [] }));
    const options = (orgs.organizations || []).map(m => `<option value="${m.organization.id}" ${m.organization.id === state.currentApp.organization_id ? 'selected' : ''}>${escapeHtml(m.organization.name)}</option>`).join('');
    document.getElementById('appTab-settings').innerHTML = `
        <div class="form-group"><label for="transferOrgId">Transfer ownership to organization</label><select id="transferOrgId">${options}</select></div>
        <button class="btn btn-primary" onclick="transferCurrentApp()">Transfer Ownership</button>
        <button class="btn btn-danger" style="margin-left:8px;" onclick="confirmDeleteCurrentApp()">Delete App</button>`;
}

async function transferCurrentApp() {
    const orgId = Number(document.getElementById('transferOrgId').value);
    await api.patch(`/apps/${state.currentApp.app_id}/transfer`, { organization_id: orgId });
    state.currentApp.organization_id = orgId;
    showToast('App ownership transferred', 'success');
}

function confirmDeleteCurrentApp() {
    confirmAction('Delete App', `Delete "${state.currentApp.display_name}"?`, async () => {
        await api.del(`/apps/${state.currentApp.app_id}`);
        showToast('App deleted', 'success');
        navigate('apps');
    });
}

async function openReleasePage(releaseId) {
    const releases = state.currentApp.releases || (await api.get(`/apps/${state.currentApp.app_id}/releases`)).releases || [];
    state.currentRelease = releases.find(r => r.id === releaseId);
    setActivePage('release-detail');
    document.getElementById('pageTitle').textContent = `Release ${state.currentRelease.version}`;
    document.getElementById('releaseDetailTitle').textContent = `Release ${state.currentRelease.version}`;
    showReleaseTab('overview');
}

async function showReleaseTab(tab) {
    document.querySelectorAll('[data-release-tab]').forEach(b => b.classList.toggle('active', b.dataset.releaseTab === tab));
    document.querySelectorAll('.release-tab').forEach(el => { el.style.display = el.id === `releaseTab-${tab}` ? 'block' : 'none'; });
    if (tab === 'overview') await renderReleaseOverview();
    if (tab === 'insights') await renderReleaseInsights();
    if (tab === 'artifacts') await renderReleaseArtifacts();
    if (tab === 'settings') renderReleaseSettings();
}

async function renderReleaseOverview() {
    const resp = await api.get(`/apps/${state.currentApp.app_id}/releases/${state.currentRelease.id}/patches`).catch(() => ({ patches: [] }));
    document.getElementById('releaseTab-overview').innerHTML = `
        <div class="stats-grid">
            <div class="stat-card primary"><div class="stat-value">${(resp.patches || []).length}</div><div class="stat-label">Patches</div></div>
            <div class="stat-card success"><div class="stat-value">${Object.keys(state.currentRelease.platform_statuses || {}).length}</div><div class="stat-label">Platforms</div></div>
        </div>
        ${renderTable(['Patch', 'Created'], (resp.patches || []).map(p => [p.patch_number || p.number || p.id, p.created_at ? new Date(p.created_at).toLocaleDateString() : '-']))}`;
}

async function renderReleaseInsights() {
    const artifacts = await api.get(`/apps/${state.currentApp.app_id}/releases/${state.currentRelease.id}/artifacts`).catch(() => ({ artifacts: [] }));
    const bytes = (artifacts.artifacts || []).reduce((sum, a) => sum + (a.size || 0), 0);
    document.getElementById('releaseTab-insights').innerHTML = `
        <div class="stats-grid">
            <div class="stat-card primary"><div class="stat-value">${(artifacts.artifacts || []).length}</div><div class="stat-label">Artifacts</div></div>
            <div class="stat-card success"><div class="stat-value">${humanSize(bytes)}</div><div class="stat-label">Artifact bytes</div></div>
            <div class="stat-card warning"><div class="stat-value">0</div><div class="stat-label">Downloads tracked</div></div>
        </div>`;
}

async function renderReleaseArtifacts() {
    const resp = await api.get(`/apps/${state.currentApp.app_id}/releases/${state.currentRelease.id}/artifacts`);
    document.getElementById('releaseTab-artifacts').innerHTML = renderTable(
        ['Platform', 'Arch', 'Size', 'Hash', 'Actions'],
        (resp.artifacts || []).map(a => [
            escapeHtml(a.platform),
            escapeHtml(a.arch),
            humanSize(a.size),
            `<code class="code">${escapeHtml(a.hash || '-')}</code>`,
            `<a class="btn btn-ghost" href="${a.url}" target="_blank" rel="noopener">Download</a>`,
        ])
    );
}

function renderReleaseSettings() {
    document.getElementById('releaseTab-settings').innerHTML = `<button class="btn btn-danger" onclick="confirmDeleteCurrentRelease()">Delete Release</button>`;
}

function confirmDeleteCurrentRelease() {
    confirmAction('Delete Release', `Delete release ${state.currentRelease.version}?`, async () => {
        await api.del(`/apps/${state.currentApp.app_id}/releases/${state.currentRelease.id}`);
        showToast('Release deleted', 'success');
        await openAppPage(state.currentApp.app_id);
    });
}

// Export functions for inline onclick handlers
window.openCreateAppModal = openCreateAppModal;
window.openCreateUserModal = openCreateUserModal;
window.openCreateOrgModal = openCreateOrgModal;
window.openAddOrgUserModal = openAddOrgUserModal;
window.loadOrganizationMembers = loadOrganizationMembers;
window.openAppPage = openAppPage;
window.showAppTab = showAppTab;
window.transferCurrentApp = transferCurrentApp;
window.confirmDeleteCurrentApp = confirmDeleteCurrentApp;
window.openReleasePage = openReleasePage;
window.showReleaseTab = showReleaseTab;
window.confirmDeleteCurrentRelease = confirmDeleteCurrentRelease;
window.verifyUserEmail = verifyUserEmail;
window.setUserAdmin = setUserAdmin;
window.confirmDeleteApp = confirmDeleteApp;
window.copyToClipboard = copyToClipboard;
window.closeModal = closeModal;


