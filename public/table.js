// public/table.js

// Token + headers utilities
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

// State
const state = {
  sort: 'name',
  dir: 'asc',
  users: [],
};

// Fetch + render
async function loadUsers() {
  const res = await fetch(`/api/users?sort=${encodeURIComponent(state.sort)}&dir=${encodeURIComponent(state.dir)}`, {
    headers: authHeaders()
  });

  if (res.status === 401 || res.status === 403) {
    const body = await res.json().catch(() => ({}));
    location.href = body.redirectTo || '/login.html';
    return;
  }

  state.users = await res.json();
  renderRows(state.users);
  updateSortIndicators();
  updateHeaderCheckboxState();
}

// Filtering
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

// Row rendering
function renderRows(users) {
  const tbody = document.getElementById('userRows');
  tbody.innerHTML = users.map(u => `
    <tr data-id="${u.id}" data-name="${(u.name||'').toLowerCase()}" data-email="${(u.email||'').toLowerCase()}">
      <td><input class="form-check-input row-check" type="checkbox" value="${u.id}"></td>
      <td>${u.name}</td>
      <td>${u.email}</td>
      <td class="text-capitalize">${u.status}</td>
      <td>${u.last_login ? new Date(u.last_login).toLocaleString() : '-'}</td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.row-check').forEach(cb => {
    cb.addEventListener('change', onRowSelectionChanged);
  });

  filterInput?.dispatchEvent(new Event('input'));

  updateToolbarButtons();
}

// Select-all behavior
const checkAll = document.getElementById('checkAll');
checkAll?.addEventListener('change', () => {
  const visibleRows = [...document.querySelectorAll('#userRows tr:not(.d-none) .row-check')];
  visibleRows.forEach(cb => cb.checked = checkAll.checked);
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

  // Grey out
  const oneSelected = checkedVisible.length === 1;
  checkAll.classList.toggle('checkall-one-selected', oneSelected);
}

// Toolbar actions
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
  if (!ids.length && action !== 'delete-unverified') return;

  let method, url, body;
  if (action === 'block' || action === 'unblock') {
    method = 'PATCH'; url = `/api/users/${action}`; body = JSON.stringify({ ids });
  } else if (action === 'delete') {
    method = 'DELETE'; url = `/api/users`; body = JSON.stringify({ ids });
  } else if (action === 'delete-unverified') {
    method = 'DELETE'; url = `/api/users/unverified`;
  }

  const res = await fetch(url, { method, headers: authHeaders(), body });
  if (!res.ok) {
    const msg = (await res.json().catch(() => ({}))).error || 'Action failed.';
    alert(msg);
    return;
  }
  await loadUsers();
}

// Bind toolbar
document.getElementById('btnBlock')?.addEventListener('click', () => bulk('block'));
document.getElementById('btnUnblock')?.addEventListener('click', () => bulk('unblock'));
document.getElementById('btnDelete')?.addEventListener('click', () => bulk('delete'));
document.getElementById('btnDeleteUnverified')?.addEventListener('click', () => bulk('delete-unverified'));

// Sorting
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

const logoutBtn = document.getElementById('logoutBtn');
logoutBtn?.addEventListener('click', () => {
  // clear tokens
  localStorage.removeItem('token');
  sessionStorage.removeItem('token');

  if (confirm('Are you sure you want to log out?')) {
    location.href = '/login.html';
  }

  location.href = '/login.html';
});

// Boot
const token = getToken();
if (!token) {
  location.href = '/login.html';
} else {
  loadUsers();
}
