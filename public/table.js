// ---------------------------
// Token + headers utilities
// ---------------------------
function getToken() {
  return sessionStorage.getItem('token') || localStorage.getItem('token');
}
function authHeaders() {
  const token = getToken();
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {})
  };
}

// ---------------------------
// State
// ---------------------------
const state = {
  sort: 'name',   // default sort by name
  dir: 'asc',     // default ascending
  users: [],
  apiPath: '/api/users' // will auto-fallback to '/users' if needed
};

// ---------------------------
// Helpers
// ---------------------------
const noticeBox = document.getElementById('tableNotice');
function showNotice(html, type = 'info') {
  if (!noticeBox) return;
  noticeBox.className = '';
  noticeBox.classList.add('px-3','pt-3',`text-${type}`);
  noticeBox.innerHTML = html;
  noticeBox.classList.remove('d-none');
}
function hideNotice() {
  if (!noticeBox) return;
  noticeBox.classList.add('d-none');
  noticeBox.innerHTML = '';
}

// ---------------------------
// Fetch + render
// ---------------------------
async function fetchUsersOnce(path) {
  const url = `${path}?sort=${encodeURIComponent(state.sort)}&dir=${encodeURIComponent(state.dir)}`;
  console.log('Fetching users from:', url);
  const res = await fetch(url, { headers: authHeaders() });
  if (res.status === 401 || res.status === 403) {
    // redirect to login if not authorized
    const body = await res.json().catch(() => ({}));
    location.href = body.redirectTo || '/login.html';
    return null;
  }
  if (!res.ok) {
    throw new Error(`Users fetch failed: ${res.status}`);
  }
  const data = await res.json();
  if (!Array.isArray(data)) {
    throw new Error('Users API did not return an array.');
  }
  return data;
}

async function loadUsers() {
  hideNotice();
  // try /api/users, fallback to /users
  try {
    let users = await fetchUsersOnce(state.apiPath);
    if (users === null) return; // redirected
    // If /api/users 404/500, try /users once
  } catch (e1) {
    console.warn('Primary users endpoint failed:', e1.message);
    try {
      state.apiPath = '/users';
      const users2 = await fetchUsersOnce(state.apiPath);
      if (users2 === null) return;
      state.users = users2;
      renderRows(state.users);
      updateSortIndicators();
      updateHeaderCheckboxState();
      if (!users2.length) showNotice('<em>No users found.</em>', 'secondary');
      return;
    } catch (e2) {
      console.error('Fallback users endpoint failed:', e2.message);
      showNotice('Failed to load users. Please try again later.', 'danger');
      return;
    }
  }

  // if first call succeeded, we’ll be here:
  const users = await fetchUsersOnce(state.apiPath);
  if (users === null) return;
  state.users = users;
  renderRows(state.users);
  updateSortIndicators();
  updateHeaderCheckboxState();
  if (!users.length) showNotice('<em>No users found.</em>', 'secondary');
}

// ---------------------------
// Filtering (client-side quick filter for name/email)
// ---------------------------
const filterInput = document.getElementById('filterInput');
filterInput?.addEventListener('input', () => {
  const q = filterInput.value.trim().toLowerCase();
  [...document.querySelectorAll('#userRows tr')].forEach(tr => {
    const name = tr.dataset.name || '';
    const email = tr.dataset.email || '';
    const show = name.includes(q) || email.includes(q);
    tr.classList.toggle('d-none', !show);
  });
  updateHeaderCheckboxState();
});

// ---------------------------
// Row rendering
// ---------------------------
function renderRows(users) {
  const tbody = document.getElementById('userRows');
  const rowsHtml = users.map(u => {
    const last = u.last_login || u.last_activity || u.created_at || null;
    const lastText = last ? new Date(last).toLocaleString() : '-';
    const name = (u.name ?? '').toString();
    const email = (u.email ?? '').toString();
    const status = (u.status ?? '').toString();

    return `
      <tr data-id="${u.id}" data-name="${name.toLowerCase()}" data-email="${email.toLowerCase()}">
        <td><input class="form-check-input row-check" type="checkbox" value="${u.id}"></td>
        <td>${escapeHtml(name)}</td>
        <td>${escapeHtml(email)}</td>
        <td class="text-capitalize">${escapeHtml(status)}</td>
        <td>${lastText}</td>
      </tr>
    `;
  }).join('');

  tbody.innerHTML = rowsHtml;

  // Bind row checkbox changes
  tbody.querySelectorAll('.row-check').forEach(cb => {
    cb.addEventListener('change', onRowSelectionChanged);
  });

  // Apply current filter, if any
  filterInput?.dispatchEvent(new Event('input'));

  updateToolbarButtons();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

// ---------------------------
// Select-all behavior
// ---------------------------
const checkAll = document.getElementById('checkAll');
checkAll?.addEventListener('change', () => {
  const visibleChecks = [...document.querySelectorAll('#userRows tr:not(.d-none) .row-check')];
  visibleChecks.forEach(cb => cb.checked = checkAll.checked);
  updateHeaderCheckboxState();
  updateToolbarButtons();
});

function onRowSelectionChanged() {
  updateHeaderCheckboxState();
  updateToolbarButtons();
}

function updateHeaderCheckboxState() {
  const allVisible = [...document.querySelectorAll('#userRows tr:not(.d-none) .row-check')];
  const checkedVisible = allVisible.filter(cb => cb.checked);

  if (allVisible.length === 0) {
    checkAll.checked = false;
    checkAll.indeterminate = false;
  } else if (checkedVisible.length === 0) {
    checkAll.checked = false;
    checkAll.indeterminate = false;
  } else if (checkedVisible.length === allVisible.length) {
    checkAll.checked = true;
    checkAll.indeterminate = false;
  } else {
    checkAll.checked = false;
    checkAll.indeterminate = true;
  }

  const oneSelected = checkedVisible.length === 1;
  checkAll.classList.toggle('checkall-one-selected', oneSelected);
}

// ---------------------------
// Toolbar actions
// ---------------------------
function selectedIds() {
  return [...document.querySelectorAll('#userRows .row-check:checked')].map(cb => Number(cb.value));
}

function updateToolbarButtons() {
  const hasSel = selectedIds().length > 0;
  ['btnBlock', 'btnUnblock', 'btnDelete'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = !hasSel;
  });
}

async function bulk(action) {
  const ids = selectedIds();
  if (!ids.length) return;

  let method, url, body;
  if (action === 'block' || action === 'unblock') {
    method = 'PATCH'; url = `/api/users/${action}`; body = JSON.stringify({ ids });
  } else if (action === 'delete') {
    method = 'DELETE'; url = `/api/users`; body = JSON.stringify({ ids });
  }

  try {
    const res = await fetch(url, { method, headers: authHeaders(), body });
    if (!res.ok) {
      const msg = (await res.json().catch(() => ({}))).error || 'Action failed.';
      alert(msg);
      return;
    }
    await loadUsers();
  } catch (err) {
    console.error('Bulk action error:', err);
    alert('Action failed.');
  }
}

document.getElementById('btnBlock')?.addEventListener('click', () => bulk('block'));
document.getElementById('btnUnblock')?.addEventListener('click', () => bulk('unblock'));
document.getElementById('btnDelete')?.addEventListener('click', () => bulk('delete'));

// ---------------------------
// Sorting
// ---------------------------
function updateSortIndicators() {
  document.querySelectorAll('th .sort-btn').forEach(btn => {
    const icon = btn.querySelector('.bi');
    const col = btn.dataset.sort;
    if (col === state.sort) {
      icon.className = `bi ${state.dir === 'asc' ? 'bi-arrow-up' : 'bi-arrow-down'} ms-1`;
      btn.classList.add('fw-semibold');
    } else {
      icon.className = 'bi bi-arrow-down-up ms-1';
      btn.classList.remove('fw-semibold');
    }
  });
}

document.querySelectorAll('th .sort-btn').forEach(btn => {
  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    const col = btn.dataset.sort;
    if (state.sort === col) {
      state.dir = (state.dir === 'asc') ? 'desc' : 'asc';
    } else {
      state.sort = col;
      state.dir = (col === 'last_login') ? 'desc' : 'asc';
    }
    await loadUsers();
  });
});

// ---------------------------
// Logout
// ---------------------------
const logoutBtn = document.getElementById('logoutBtn');
logoutBtn?.addEventListener('click', () => {
  localStorage.removeItem('token');
  sessionStorage.removeItem('token');
  location.href = '/login.html';
});

// ---------------------------
// Boot
// ---------------------------
const token = getToken();
if (!token) {
  location.href = '/login.html';
} else {
  loadUsers();
}
