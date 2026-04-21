// Password-gated SPA.
// Loads two encrypted bundles: core (everything except per-category scorecards)
// and scorecards (lazy, fetched on first click into a /study/categories/<slug> page).
// All user-facing labels come from the decrypted core bundle; this file has no
// strategic text of its own.

const state = {
  password: null,     // kept in memory so we can re-derive per bundle (each bundle has its own salt)
  core: null,
  scorecards: null,
  scorecardsLoading: null,
};

// ─────────────── crypto ───────────────
async function deriveKey(password, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new Uint8Array(salt), iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

// Fetch a bundle pair (.enc + .meta.json), derive its key from the password,
// decrypt, gunzip, parse JSON. Each bundle has its own salt, so the key must
// be re-derived per bundle — we can't reuse a key derived for a different one.
async function fetchAndDecrypt(encUrl, metaUrl, password) {
  const [meta, encBuf] = await Promise.all([
    fetch(metaUrl).then(r => r.json()),
    fetch(encUrl).then(r => r.arrayBuffer()),
  ]);
  const key = await deriveKey(password, meta.salt, meta.iterations);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(meta.iv) },
    key,
    encBuf
  );
  // Decompress gzip
  const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));
  const text = await new Response(stream).text();
  return { data: JSON.parse(text) };
}

// ─────────────── gate ───────────────
const PW_STORAGE_KEY = 'auth.pw';

async function unlock(password, { auto = false } = {}) {
  const btn = document.getElementById('gate-btn');
  const err = document.getElementById('gate-err');
  if (btn) btn.disabled = true;
  if (err) err.innerHTML = 'Decrypting<span class="loading"></span>';
  try {
    // Try decrypting core; if password is wrong, AES-GCM auth tag fails here.
    const { data } = await fetchAndDecrypt('core.enc', 'core.meta.json', password);
    state.password = password;
    state.core = data;
    try { localStorage.setItem(PW_STORAGE_KEY, password); } catch {}
    bootApp();
  } catch (e) {
    if (auto) {
      // Stored password no longer works (rebuilt with different password, or
      // user-cleared, or corrupted). Drop it silently and show the gate.
      try { localStorage.removeItem(PW_STORAGE_KEY); } catch {}
      const form = document.getElementById('gate-form');
      if (form) form.style.display = '';
      if (err) err.innerHTML = '';
      if (btn) btn.disabled = false;
    } else {
      if (btn) btn.disabled = false;
      if (err) err.textContent = 'Incorrect password.';
    }
  }
}

document.getElementById('gate-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  unlock(document.getElementById('pw').value);
});

// Auto-unlock if a valid password is cached from a previous visit.
(function tryAutoUnlock() {
  let stored = null;
  try { stored = localStorage.getItem(PW_STORAGE_KEY); } catch {}
  if (stored) {
    const form = document.getElementById('gate-form');
    if (form) form.style.display = 'none';
    const err = document.getElementById('gate-err');
    if (err) err.innerHTML = 'Unlocking<span class="loading"></span>';
    unlock(stored, { auto: true });
  }
})();

// ─────────────── app shell ───────────────
function bootApp() {
  const root = document.getElementById('root');
  root.innerHTML = `
    <div class="app">
      <nav class="sidebar" id="sidebar"></nav>
      <main id="main"></main>
    </div>
  `;
  renderSidebar();
  window.addEventListener('hashchange', () => route());
  // Delegated click handler for the download-bundle button on the "continue" page.
  document.addEventListener('click', (ev) => {
    const btn = ev.target.closest('[data-action="download-bundle"]');
    if (btn) { ev.preventDefault(); downloadBundle(btn); }
  });
  route();
}

async function downloadBundle(btn) {
  const statusEl = btn.parentElement.querySelector('.download-status');
  btn.disabled = true;
  if (statusEl) statusEl.innerHTML = 'Decrypting<span class="loading"></span>';
  try {
    const [meta, encBuf] = await Promise.all([
      fetch('bundle.meta.json').then(r => r.json()),
      fetch('bundle.enc').then(r => r.arrayBuffer()),
    ]);
    const key = await deriveKey(state.password, meta.salt, meta.iterations);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(meta.iv) },
      key,
      encBuf
    );
    const blob = new Blob([plain], { type: 'application/zip' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = meta.filename || 'bundle.zip';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    btn.disabled = false;
    if (statusEl) statusEl.textContent = 'Download started. If nothing happened, click again.';
  } catch (e) {
    console.error(e);
    btn.disabled = false;
    if (statusEl) statusEl.textContent = 'Download failed — try refreshing the page.';
  }
}

// Render the sidebar by mounting a pre-built HTML string from the decrypted
// bundle. All user-facing labels live in the encrypted core bundle; this
// file contains no strategic labels. A <!--SCORECARDS_TREE--> placeholder
// in the baked HTML is replaced here with a dynamically-computed tree of
// per-category scorecards derived from the scorecard index + taxonomy.
function renderSidebar() {
  const nav = document.getElementById('sidebar');
  const d = state.core;
  const byGroup = {};
  for (const row of d.scorecardIndex) {
    (byGroup[row.group_display] ??= []).push(row);
  }
  const groupOrder = d.taxonomyGroups.map(g => g.display);
  const scorecardsTree = groupOrder.map(g => {
    const rows = (byGroup[g] || []).sort((a, b) => a.name.localeCompare(b.name));
    if (!rows.length) return '';
    const items = rows.map(r => `<a data-href="study/categories/${r.slug}" href="#/study/categories/${r.slug}">${r.name}</a>`).join('');
    return `<details><summary class="group-label">${g}</summary><div class="subtree">${items}</div></details>`;
  }).join('');
  nav.innerHTML = (d.sidebarHtml || '').replace('<!--SCORECARDS_TREE-->', scorecardsTree);
}

// ─────────────── routing ───────────────
const DEFAULT_ROUTE = 'brief';

async function route() {
  const hash = location.hash.replace(/^#\/?/, '').replace(/\/$/, '') || DEFAULT_ROUTE;
  // Update active link state
  document.querySelectorAll('nav a').forEach(a => {
    a.classList.toggle('active', a.getAttribute('data-href') === hash);
  });

  const main = document.getElementById('main');

  // scorecard index — rendered at runtime (sortable)
  if (hash === 'study/scorecards') {
    renderScorecardIndex(main);
    return;
  }

  // per-category page — lazy-load bundle
  if (hash.startsWith('study/categories/')) {
    await ensureScorecards(main);
    if (!state.scorecards) return;
    const page = state.scorecards.pages[hash];
    if (page) { renderPage(main, page); return; }
    renderNotFound(main, hash);
    return;
  }

  // taxonomy — rendered at runtime
  if (hash === 'study/taxonomy') {
    renderTaxonomy(main);
    return;
  }

  const page = state.core.pages[hash];
  if (page) { renderPage(main, page); return; }
  renderNotFound(main, hash);
}

function renderPage(main, page) {
  const crumb = (page.crumb || []).map((c, i, a) =>
    i === a.length - 1 ? `<span>${c.label}</span>` : `<a href="#/${c.href}">${c.label}</a>`
  ).join(' / ');
  main.innerHTML = `
    ${crumb ? `<div class="crumb">${crumb}</div>` : ''}
    <article>${page.html}</article>
  `;
  main.scrollTop = 0;
  window.scrollTo(0, 0);
  if (window.hljs) {
    main.querySelectorAll('pre code').forEach(el => window.hljs.highlightElement(el));
  }
}

function renderNotFound(main, hash) {
  main.innerHTML = `<div class="crumb">not found</div><h1>Page not found</h1><p>No entry at <code>${hash}</code>.</p>`;
}

async function ensureScorecards(main) {
  if (state.scorecards) return;
  if (state.scorecardsLoading) { await state.scorecardsLoading; return; }
  main.innerHTML = `<div class="lazy-note">Decrypting per-category scorecards<span class="loading"></span></div>`;
  state.scorecardsLoading = fetchAndDecrypt('scorecards.enc', 'scorecards.meta.json', state.password)
    .then(({ data }) => { state.scorecards = data; })
    .catch(e => { main.innerHTML = `<p>Failed to load scorecards bundle: ${e.message || e.toString()}</p>`; console.error(e); });
  await state.scorecardsLoading;
  state.scorecardsLoading = null;
}

// ─────────────── scorecard sortable index ───────────────
function renderScorecardIndex(main) {
  const rows = state.core.scorecardIndex;
  const v = state.core.views?.scorecardIndex || {};
  const cols = v.columns || {};
  main.innerHTML = `
    <div class="crumb"><a href="#/${v.crumbBackSlug || ''}">${v.crumbBackLabel || ''}</a> / ${v.crumbMiddle || ''} / ${v.crumbEnd || ''}</div>
    <h1>${v.h1 || ''}</h1>
    <p>${v.intro || ''}</p>
    <p><em>${v.sortHint || ''}</em></p>
    <table class="score-index">
      <thead><tr>
        <th data-k="name">${cols.name || ''}</th>
        <th data-k="group_display">${cols.group || ''}</th>
        <th data-k="composite" class="num sort-desc">${cols.composite || ''}</th>
        <th data-k="band">${cols.band || ''}</th>
        <th data-k="exclusivity" class="num">${cols.exclusivity || ''}</th>
        <th data-k="value_per_lab_year" class="num">${cols.valuePerLabYear || ''}</th>
      </tr></thead>
      <tbody id="score-body"></tbody>
    </table>
  `;
  let sortKey = 'composite';
  let sortDir = -1;
  function renderBody() {
    const sorted = [...rows].sort((a, b) => {
      const av = a[sortKey], bv = b[sortKey];
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * sortDir;
      return String(av ?? '').localeCompare(String(bv ?? '')) * sortDir;
    });
    document.getElementById('score-body').innerHTML = sorted.map(r => `
      <tr data-slug="${r.slug}">
        <td>${r.name}</td>
        <td>${r.group_display}</td>
        <td class="num">${r.composite != null ? r.composite.toFixed(2) : '—'}</td>
        <td class="num"><span class="band-${(r.band || '').toLowerCase().replace(/\s+/g,'-')}">${r.band || '—'}</span></td>
        <td class="num">${r.exclusivity != null ? r.exclusivity : '—'}</td>
        <td class="num">${r.value_per_lab_year || '—'}</td>
      </tr>
    `).join('');
    document.querySelectorAll('.score-index th').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
      if (th.dataset.k === sortKey) th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
    });
  }
  renderBody();
  document.querySelectorAll('.score-index th').forEach(th => {
    th.addEventListener('click', () => {
      const k = th.dataset.k;
      if (k === sortKey) sortDir = -sortDir;
      else { sortKey = k; sortDir = (typeof rows[0][k] === 'number') ? -1 : 1; }
      renderBody();
    });
  });
  document.getElementById('score-body').addEventListener('click', (e) => {
    const tr = e.target.closest('tr');
    if (tr && tr.dataset.slug) location.hash = `#/study/categories/${tr.dataset.slug}`;
  });
}

// ─────────────── taxonomy view ───────────────
function renderTaxonomy(main) {
  const groups = state.core.taxonomyGroups;
  const v = state.core.views?.taxonomy || {};
  const items = groups.map(g => `
    <details open>
      <summary>${g.display} <span style="color:var(--ink-soft); font-variant: normal; letter-spacing: 0; font-weight: 400;">(${g.categories.length})</span></summary>
      <ul class="cat-list">
        ${g.categories.map(c => `<li><a href="#/study/categories/${c.slug}">${c.name}</a> <span style="color:var(--ink-soft); font-size:0.85em;">— ${c.short || ''}</span></li>`).join('')}
      </ul>
    </details>
  `).join('');
  const intro = (v.intro || '')
    .replace('{{DIR}}', `<code>${v.dirRef || ''}</code>`)
    .replace('{{VERSION}}', String(state.core.taxonomyMeta.version))
    .replace('{{DATE}}', String(state.core.taxonomyMeta.date));
  main.innerHTML = `
    <div class="crumb">${v.crumbStart || ''} / ${v.crumbEnd || ''}</div>
    <h1>${v.h1 || ''}</h1>
    <p>${intro}</p>
    <div class="taxonomy-tree">${items}</div>
  `;
}
