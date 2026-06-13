const SESSION_COOKIE = 'bpm_session';
const SESSION_DAYS = 7;
const DEMO_PASSWORD = 'admin123';

export default {
  async fetch(request, env) {
    try {
      await ensureSchema(env);
      const url = new URL(request.url);

      if (url.pathname === '/' && request.method === 'GET') return htmlResponse(APP_HTML);
      if (url.pathname === '/api/auth/login' && request.method === 'POST') return login(request, env);
      if (url.pathname === '/api/auth/logout' && request.method === 'POST') return logout(request, env);

      if (url.pathname.startsWith('/api/')) {
        const user = await requireUser(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        if (url.pathname === '/api/me' && request.method === 'GET') return json({ user });
        if (url.pathname === '/api/announcements' && request.method === 'GET') return listAnnouncements(env);
        if (url.pathname === '/api/announcements' && request.method === 'POST') return createAnnouncement(request, env, user);
        if (url.pathname === '/api/messages' && request.method === 'GET') return listMessages(env, user);
        if (url.pathname === '/api/roles' && request.method === 'GET') return listRoles(env, user);
        if (url.pathname === '/api/roles' && request.method === 'POST') return createRole(request, env, user);
        if (url.pathname === '/api/users' && request.method === 'GET') return listUsers(env, user);
        if (url.pathname === '/api/users' && request.method === 'POST') return createUser(request, env, user);
        if (url.pathname.startsWith('/api/users/') && request.method === 'PATCH') {
          const id = Number(url.pathname.split('/').pop());
          return updateUser(request, env, user, id);
        }
      }

      return new Response('Not found', { status: 404 });
    } catch (error) {
      return json({ error: error.message || 'Server error' }, 500);
    }
  }
};

async function ensureSchema(env) {
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      email TEXT,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      system_role TEXT NOT NULL DEFAULT 'employee',
      roles_json TEXT NOT NULL DEFAULT '[]',
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role_key TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      read_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`)
  ]);

  await env.DB.prepare(`INSERT OR IGNORE INTO roles (role_key, name, description) VALUES
    ('announcement_owner', '公告負責人', '可新增入口公告'),
    ('employee', '一般人員', '一般員工入口權限'),
    ('knowledge_admin', '知識庫管理員', '預留知識庫維護角色')`).run();

  const adminExists = await env.DB.prepare('SELECT id FROM users WHERE account = ?').bind('admin').first();
  if (!adminExists) {
    const admin = await hashPassword(DEMO_PASSWORD);
    const employee = await hashPassword('employee123');
    await env.DB.prepare(`INSERT INTO users
      (account, display_name, email, password_salt, password_hash, system_role, roles_json)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind('admin', '系統管理員', 'admin@example.com', admin.salt, admin.hash, 'admin', JSON.stringify(['announcement_owner']))
      .run();
    await env.DB.prepare(`INSERT INTO users
      (account, display_name, email, password_salt, password_hash, system_role, roles_json)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind('employee', '一般員工', 'employee@example.com', employee.salt, employee.hash, 'employee', JSON.stringify(['employee']))
      .run();
    const adminUser = await env.DB.prepare('SELECT id FROM users WHERE account = ?').bind('admin').first();
    const employeeUser = await env.DB.prepare('SELECT id FROM users WHERE account = ?').bind('employee').first();
    await env.DB.prepare('INSERT INTO announcements (title, body, created_by) VALUES (?, ?, ?)')
      .bind('歡迎使用 BPM 入口系統', '這是 Cloudflare Workers + D1 的第一版入口雛形。', adminUser.id)
      .run();
    await env.DB.prepare('INSERT INTO messages (user_id, title, body) VALUES (?, ?, ?)')
      .bind(employeeUser.id, '待辦提醒', '未來這裡會整合簽核待辦、退回通知與系統訊息。')
      .run();
  }
}

async function login(request, env) {
  const body = await readJson(request);
  const account = String(body.account || '').trim();
  const password = String(body.password || '');
  if (!account || !password) return json({ error: '請輸入帳號與密碼' }, 400);

  const row = await env.DB.prepare('SELECT * FROM users WHERE account = ? AND active = 1').bind(account).first();
  if (!row) return json({ error: '帳號或密碼錯誤' }, 401);
  const hash = await digest(`${row.password_salt}:${password}`);
  if (hash !== row.password_hash) return json({ error: '帳號或密碼錯誤' }, 401);

  const token = randomToken();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, row.id, expires)
    .run();

  return json(
    { user: sanitizeUser(row) },
    200,
    { 'Set-Cookie': `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}` }
  );
}

async function logout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  return json({ ok: true }, 200, { 'Set-Cookie': `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0` });
}

async function requireUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(`
    SELECT users.* FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token = ? AND sessions.expires_at > datetime('now') AND users.active = 1
  `).bind(token).first();
  return row ? sanitizeUser(row) : null;
}

async function listAnnouncements(env) {
  const { results } = await env.DB.prepare(`
    SELECT announcements.id, announcements.title, announcements.body, announcements.created_at,
      users.display_name AS created_by_name
    FROM announcements
    JOIN users ON users.id = announcements.created_by
    ORDER BY announcements.created_at DESC
    LIMIT 20
  `).all();
  return json({ announcements: results });
}

async function createAnnouncement(request, env, user) {
  if (!canManageAnnouncements(user)) return json({ error: '沒有公告管理權限' }, 403);
  const body = await readJson(request);
  const title = String(body.title || '').trim();
  const content = String(body.body || '').trim();
  if (!title || !content) return json({ error: '請輸入公告標題與內容' }, 400);
  await env.DB.prepare('INSERT INTO announcements (title, body, created_by) VALUES (?, ?, ?)')
    .bind(title, content, user.id)
    .run();
  return listAnnouncements(env);
}

async function listMessages(env, user) {
  const { results } = await env.DB.prepare(`
    SELECT id, title, body, read_at, created_at FROM messages
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT 20
  `).bind(user.id).all();
  return json({ messages: results });
}

async function listRoles(env, user) {
  if (!isAdmin(user)) return json({ error: '沒有角色管理權限' }, 403);
  const { results } = await env.DB.prepare('SELECT * FROM roles ORDER BY id').all();
  return json({ roles: results });
}

async function createRole(request, env, user) {
  if (!isAdmin(user)) return json({ error: '沒有角色管理權限' }, 403);
  const body = await readJson(request);
  const key = String(body.role_key || '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const name = String(body.name || '').trim();
  const description = String(body.description || '').trim();
  if (!key || !name) return json({ error: '請輸入角色代碼與名稱' }, 400);
  await env.DB.prepare('INSERT INTO roles (role_key, name, description) VALUES (?, ?, ?)')
    .bind(key, name, description)
    .run();
  return listRoles(env, user);
}

async function listUsers(env, user) {
  if (!isAdmin(user)) return json({ error: '沒有帳號管理權限' }, 403);
  const { results } = await env.DB.prepare(`
    SELECT id, account, display_name, email, system_role, roles_json, active, created_at
    FROM users ORDER BY id
  `).all();
  return json({ users: results.map(sanitizeUser) });
}

async function createUser(request, env, user) {
  if (!isAdmin(user)) return json({ error: '沒有帳號管理權限' }, 403);
  const body = await readJson(request);
  const account = String(body.account || '').trim();
  const displayName = String(body.display_name || '').trim();
  const email = String(body.email || '').trim();
  const password = String(body.password || 'ChangeMe123');
  const systemRole = body.system_role === 'admin' ? 'admin' : 'employee';
  const roles = Array.isArray(body.roles) ? body.roles : [];
  if (!account || !displayName) return json({ error: '請輸入帳號與姓名' }, 400);
  const passwordData = await hashPassword(password);
  await env.DB.prepare(`INSERT INTO users
    (account, display_name, email, password_salt, password_hash, system_role, roles_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .bind(account, displayName, email, passwordData.salt, passwordData.hash, systemRole, JSON.stringify(roles))
    .run();
  return listUsers(env, user);
}

async function updateUser(request, env, user, id) {
  if (!isAdmin(user)) return json({ error: '沒有帳號管理權限' }, 403);
  const body = await readJson(request);
  const displayName = String(body.display_name || '').trim();
  const email = String(body.email || '').trim();
  const systemRole = body.system_role === 'admin' ? 'admin' : 'employee';
  const roles = Array.isArray(body.roles) ? body.roles : [];
  const active = body.active ? 1 : 0;
  if (!id || !displayName) return json({ error: '資料不完整' }, 400);
  await env.DB.prepare(`
    UPDATE users SET display_name = ?, email = ?, system_role = ?, roles_json = ?, active = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(displayName, email, systemRole, JSON.stringify(roles), active, id).run();
  return listUsers(env, user);
}

function isAdmin(user) {
  return user.system_role === 'admin';
}

function canManageAnnouncements(user) {
  return isAdmin(user) || user.roles.includes('announcement_owner');
}

function sanitizeUser(row) {
  return {
    id: row.id,
    account: row.account,
    display_name: row.display_name,
    email: row.email || '',
    system_role: row.system_role,
    roles: safeParse(row.roles_json, []),
    active: Boolean(row.active),
    created_at: row.created_at
  };
}

function safeParse(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

async function hashPassword(password) {
  const salt = randomToken(12);
  return { salt, hash: await digest(`${salt}:${password}`) };
}

async function digest(value) {
  const data = new TextEncoder().encode(value);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hashBuffer)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function randomToken(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const item = cookie.split(';').map(part => part.trim()).find(part => part.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.split('=').slice(1).join('=')) : '';
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...headers
    }
  });
}

function htmlResponse(html) {
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

const APP_HTML = `<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BPM Portal</title>
  <style>
    :root{--bg:#f5f7fb;--ink:#16202f;--muted:#607086;--panel:#fff;--line:#d9e0ec;--accent:#1d6eea;--green:#23785f;--danger:#bd3b3b}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.55}
    button,input,textarea,select{font:inherit}.shell{width:min(1180px,calc(100% - 28px));margin:0 auto}.hidden{display:none!important}
    header{border-bottom:1px solid var(--line);background:#fff}.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;min-height:68px}
    .brand{display:flex;align-items:center;gap:12px;font-weight:850}.mark{display:grid;place-items:center;width:38px;height:38px;border-radius:8px;background:var(--ink);color:#fff}
    .userline{color:var(--muted);font-size:14px}.layout{display:grid;grid-template-columns:230px minmax(0,1fr);gap:18px;padding:18px 0 44px}
    nav,.card{border:1px solid var(--line);border-radius:8px;background:var(--panel)}nav{padding:10px;height:max-content;position:sticky;top:14px}
    nav button{width:100%;border:0;border-radius:7px;background:transparent;color:var(--muted);padding:11px 12px;text-align:left;cursor:pointer;font-weight:750}
    nav button.active,nav button:hover{background:#edf4ff;color:var(--accent)}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
    .card{padding:18px}.card h2,.card h3{margin:0 0 10px}.card p{margin:0;color:var(--muted)}.stat{font-size:30px;font-weight:900}
    .login{min-height:100vh;display:grid;place-items:center;padding:24px}.login-card{width:min(420px,100%);border:1px solid var(--line);border-radius:8px;background:#fff;padding:28px;box-shadow:0 24px 70px rgba(22,32,47,.12)}
    label{display:grid;gap:6px;margin-top:12px;color:var(--muted);font-size:13px;font-weight:750}input,textarea,select{width:100%;border:1px solid var(--line);border-radius:8px;padding:11px 12px;background:#fff;color:var(--ink)}
    textarea{min-height:96px;resize:vertical}.btn{border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink);min-height:42px;padding:0 14px;cursor:pointer;font-weight:800}
    .btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}.btn.danger{background:var(--danger);border-color:var(--danger);color:#fff}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
    .list{display:grid;gap:10px}.item{border:1px solid var(--line);border-radius:8px;padding:14px;background:#fff}.meta{color:var(--muted);font-size:13px}.badge{display:inline-flex;align-items:center;min-height:24px;border-radius:8px;background:#eef3fb;color:#30425b;padding:0 8px;font-size:12px;font-weight:800;margin-right:6px}
    table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:8px;overflow:hidden}th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;font-size:14px}th{color:var(--muted);background:#f9fbfe}
    .form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.wide{grid-column:1/-1}.notice{padding:10px 12px;border-radius:8px;background:#eef8f3;color:var(--green);font-weight:750}.error{background:#fff0f0;color:var(--danger)}
    @media(max-width:860px){.layout,.grid,.form-grid{grid-template-columns:1fr}nav{position:static}.topbar{align-items:flex-start;flex-direction:column}}
  </style>
</head>
<body>
  <section id="loginView" class="login">
    <form id="loginForm" class="login-card">
      <div class="brand"><span class="mark">B</span><div><h1>BPM Portal</h1><p class="meta">簽核入口與內部協作平台 MVP</p></div></div>
      <label>帳號<input name="account" autocomplete="username" value="admin" required></label>
      <label>密碼<input name="password" type="password" autocomplete="current-password" value="admin123" required></label>
      <div class="actions"><button class="btn primary" type="submit">登入</button></div>
      <p class="meta">Demo：admin / admin123，一般員工：employee / employee123</p>
      <p id="loginError" class="notice error hidden"></p>
    </form>
  </section>

  <section id="appView" class="hidden">
    <header><div class="shell topbar"><div class="brand"><span class="mark">B</span><span>BPM Portal</span></div><div class="userline" id="userLine"></div><button class="btn" id="logoutBtn">登出</button></div></header>
    <main class="shell layout">
      <nav id="nav"></nav>
      <section id="content"></section>
    </main>
  </section>

  <script>
    const state = { user:null, announcements:[], messages:[], users:[], roles:[], view:'dashboard' };
    const roleLabels = { announcement_owner:'公告負責人', employee:'一般人員', knowledge_admin:'知識庫管理員' };
    const api = async (url, options={}) => {
      const res = await fetch(url, { credentials:'same-origin', headers:{ 'Content-Type':'application/json' }, ...options });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || '操作失敗');
      return data;
    };
    const $ = (id) => document.getElementById(id);
    const escapeHtml = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const isAdmin = () => state.user?.system_role === 'admin';
    const canAnnouncement = () => isAdmin() || state.user?.roles?.includes('announcement_owner');

    $('loginForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      $('loginError').classList.add('hidden');
      const form = new FormData(event.currentTarget);
      try {
        const data = await api('/api/auth/login', { method:'POST', body: JSON.stringify(Object.fromEntries(form)) });
        state.user = data.user;
        await loadApp();
      } catch (error) {
        $('loginError').textContent = error.message;
        $('loginError').classList.remove('hidden');
      }
    });
    $('logoutBtn').addEventListener('click', async () => {
      await api('/api/auth/logout', { method:'POST', body:'{}' });
      location.reload();
    });

    async function boot() {
      try {
        const data = await api('/api/me');
        state.user = data.user;
        await loadApp();
      } catch {
        $('loginView').classList.remove('hidden');
        $('appView').classList.add('hidden');
      }
    }

    async function loadApp() {
      $('loginView').classList.add('hidden');
      $('appView').classList.remove('hidden');
      $('userLine').textContent = \`\${state.user.display_name}｜\${state.user.system_role === 'admin' ? '系統管理員' : '一般員工'}｜\${state.user.roles.map(r => roleLabels[r] || r).join('、') || '無角色'}\`;
      await refreshData();
      renderNav();
      render();
    }

    async function refreshData() {
      const base = [api('/api/announcements'), api('/api/messages')];
      if (isAdmin()) base.push(api('/api/users'), api('/api/roles'));
      const result = await Promise.all(base);
      state.announcements = result[0].announcements;
      state.messages = result[1].messages;
      if (isAdmin()) {
        state.users = result[2].users;
        state.roles = result[3].roles;
      }
    }

    function renderNav() {
      const items = [
        ['dashboard','入口首頁'],
        ['announcements','公告'],
        ['messages','我的訊息'],
        ['future','未來模組']
      ];
      if (isAdmin()) items.push(['users','帳號管理'], ['roles','角色管理']);
      $('nav').innerHTML = items.map(([key,label]) => \`<button class="\${state.view === key ? 'active' : ''}" data-view="\${key}">\${label}</button>\`).join('');
      document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => { state.view = btn.dataset.view; renderNav(); render(); }));
    }

    function render() {
      if (state.view === 'dashboard') renderDashboard();
      if (state.view === 'announcements') renderAnnouncements();
      if (state.view === 'messages') renderMessages();
      if (state.view === 'users') renderUsers();
      if (state.view === 'roles') renderRoles();
      if (state.view === 'future') renderFuture();
    }

    function renderDashboard() {
      $('content').innerHTML = \`
        <div class="grid">
          <div class="card"><span class="meta">公告</span><div class="stat">\${state.announcements.length}</div><p>最新內部公告與政策。</p></div>
          <div class="card"><span class="meta">我的訊息</span><div class="stat">\${state.messages.length}</div><p>個人待辦與系統通知。</p></div>
          <div class="card"><span class="meta">身份</span><div class="stat">\${isAdmin() ? 'Admin' : 'Staff'}</div><p>\${state.user.display_name}</p></div>
        </div>
        <div class="card" style="margin-top:14px"><h2>入口摘要</h2><p>這是 BPM 入口第一版，後續可接簽核流程、留言板、聊天室、討論區與知識庫。</p></div>
      \`;
    }

    function renderAnnouncements() {
      $('content').innerHTML = \`
        <div class="card">
          <h2>公告</h2>
          \${canAnnouncement() ? announcementForm() : ''}
          <div class="list" id="announcementList">\${state.announcements.map(a => \`
            <article class="item"><h3>\${escapeHtml(a.title)}</h3><p>\${escapeHtml(a.body)}</p><p class="meta">\${escapeHtml(a.created_by_name)} · \${escapeHtml(a.created_at)}</p></article>
          \`).join('') || '<p class="meta">目前沒有公告。</p>'}</div>
        </div>
      \`;
      const form = $('announcementForm');
      if (form) form.addEventListener('submit', createAnnouncement);
    }

    function announcementForm() {
      return \`<form id="announcementForm" class="form-grid" style="margin:12px 0 18px">
        <label>標題<input name="title" required></label>
        <label class="wide">內容<textarea name="body" required></textarea></label>
        <div class="actions wide"><button class="btn primary" type="submit">新增公告</button></div>
      </form>\`;
    }

    async function createAnnouncement(event) {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      const data = await api('/api/announcements', { method:'POST', body: JSON.stringify(Object.fromEntries(form)) });
      state.announcements = data.announcements;
      renderAnnouncements();
    }

    function renderMessages() {
      $('content').innerHTML = \`<div class="card"><h2>我的訊息</h2><div class="list">\${state.messages.map(m => \`
        <article class="item"><h3>\${escapeHtml(m.title)}</h3><p>\${escapeHtml(m.body)}</p><p class="meta">\${escapeHtml(m.created_at)}</p></article>
      \`).join('') || '<p class="meta">目前沒有訊息。</p>'}</div></div>\`;
    }

    function renderUsers() {
      $('content').innerHTML = \`
        <div class="card">
          <h2>帳號管理</h2>
          <form id="userForm" class="form-grid">
            <label>帳號<input name="account" required></label>
            <label>姓名<input name="display_name" required></label>
            <label>Email<input name="email" type="email"></label>
            <label>初始密碼<input name="password" value="ChangeMe123"></label>
            <label>系統身份<select name="system_role"><option value="employee">一般員工</option><option value="admin">系統管理員</option></select></label>
            <label>角色代碼，逗號分隔<input name="roles" placeholder="employee,announcement_owner"></label>
            <div class="actions wide"><button class="btn primary" type="submit">新增帳號</button></div>
          </form>
        </div>
        <div class="card" style="margin-top:14px"><table><thead><tr><th>帳號</th><th>姓名</th><th>身份</th><th>角色</th><th>狀態</th></tr></thead><tbody>
          \${state.users.map(u => \`<tr><td>\${escapeHtml(u.account)}</td><td>\${escapeHtml(u.display_name)}</td><td>\${escapeHtml(u.system_role)}</td><td>\${u.roles.map(r => \`<span class="badge">\${escapeHtml(roleLabels[r] || r)}</span>\`).join('')}</td><td>\${u.active ? '啟用' : '停用'}</td></tr>\`).join('')}
        </tbody></table></div>
      \`;
      $('userForm').addEventListener('submit', createUser);
    }

    async function createUser(event) {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      const data = Object.fromEntries(form);
      data.roles = String(data.roles || '').split(',').map(v => v.trim()).filter(Boolean);
      const result = await api('/api/users', { method:'POST', body: JSON.stringify(data) });
      state.users = result.users;
      renderUsers();
    }

    function renderRoles() {
      $('content').innerHTML = \`
        <div class="card">
          <h2>角色管理</h2>
          <form id="roleForm" class="form-grid">
            <label>角色代碼<input name="role_key" placeholder="workflow_reviewer" required></label>
            <label>角色名稱<input name="name" placeholder="簽核負責人" required></label>
            <label class="wide">描述<input name="description" placeholder="可自訂未來流程權限"></label>
            <div class="actions wide"><button class="btn primary" type="submit">新增角色</button></div>
          </form>
        </div>
        <div class="card" style="margin-top:14px"><div class="list">\${state.roles.map(r => \`<div class="item"><h3>\${escapeHtml(r.name)} <span class="badge">\${escapeHtml(r.role_key)}</span></h3><p>\${escapeHtml(r.description || '')}</p></div>\`).join('')}</div></div>
      \`;
      $('roleForm').addEventListener('submit', createRole);
    }

    async function createRole(event) {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      const result = await api('/api/roles', { method:'POST', body: JSON.stringify(Object.fromEntries(form)) });
      state.roles = result.roles;
      renderRoles();
    }

    function renderFuture() {
      $('content').innerHTML = \`
        <div class="grid">
          <div class="card"><h3>留言板</h3><p>預留：部門留言、簽核意見牆。</p></div>
          <div class="card"><h3>聊天室</h3><p>預留：WebSocket 或 Durable Objects 即時聊天。</p></div>
          <div class="card"><h3>討論區</h3><p>預留：議題分類、回覆、標籤。</p></div>
          <div class="card"><h3>知識庫</h3><p>預留：文章、版本、權限與全文搜尋。</p></div>
          <div class="card"><h3>BPM 簽核</h3><p>下一階段：表單、流程節點、簽核紀錄、退回、代理人。</p></div>
          <div class="card"><h3>系統設定</h3><p>預留：組織、部門、角色、通知模板。</p></div>
        </div>\`;
    }

    boot();
  </script>
</body>
</html>`;
