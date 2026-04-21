// Static site build.
// Usage: node build.mjs [--password=<pw>]
// Walks the configured source tree, converts markdown -> HTML, bundles into
// core.json + scorecards.json, gzips, and encrypts each with AES-GCM
// using PBKDF2(SHA-256, 600k iterations) from the password.
//
// All user-facing labels and descriptive text are loaded from
// `content-private.json` (gitignored) at build time, so the public repo
// contains only generic scaffolding.
//
// Re-runnable: safe to invoke after any .md edit. Idempotent outputs.

import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import MarkdownIt from 'markdown-it';
import mdFootnote from 'markdown-it-footnote';
import mdKatex from '@vscode/markdown-it-katex';
import yaml from 'js-yaml';

const gzip = promisify(zlib.gzip);
const execFileAsync = promisify(execFile);
const HERE = path.dirname(new URL(import.meta.url).pathname);
const ROOT = path.resolve(HERE, '..');
const SITE_URL = 'https://atqamar.github.io/2cac1b2c/';

// ─────────────── CLI / config ───────────────
const args = Object.fromEntries(
  process.argv.slice(2).map(a => a.startsWith('--') ? a.slice(2).split('=') : [a, true])
);
const PASSWORD = args.password || process.env.SITE_PASSWORD || 'sigma';
const PBKDF2_ITERATIONS = 600000;

// ─────────────── markdown renderer ───────────────
const md = new MarkdownIt({
  html: true,
  linkify: true,
  typographer: true,
  breaks: false,
})
  .use(mdFootnote)
  .use(mdKatex.default || mdKatex, { throwOnError: false, errorColor: '#7a1f1f' });

// ─────────────── helpers ───────────────
async function exists(p) { try { await fs.stat(p); return true; } catch { return false; } }
async function readIfExists(p) { try { return await fs.readFile(p, 'utf8'); } catch { return null; } }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function loadContent() {
  const p = path.join(HERE, 'content-private.json');
  if (!(await exists(p))) {
    throw new Error(`Missing ${p}. This file contains all user-facing labels and is required for the build.`);
  }
  return JSON.parse(await fs.readFile(p, 'utf8'));
}

// Repo-path → hash route mapping, constructed dynamically from the content
// config (so no explicit source filenames live in this file). Parameterized
// patterns (thread letters, report slug wildcards) are kept generic here —
// they don't expose strategic names on their own.
function buildPathToRoute(content) {
  const routes = [];
  const esc = (s) => s.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
  for (const ap of content.arcPages) {
    if (ap.source) routes.push([new RegExp('^' + esc(ap.source) + '$'), ap.slug]);
  }
  for (const d of content.studyDocs) {
    if (d.source) routes.push([new RegExp('^' + esc(d.source) + '$'), `study/${d.slug}`]);
  }
  routes.push([/^research\/round-2\/([^/]+)\.md$/,                          (m) => `round-2/${m[1]}`]);
  routes.push([/^research\/threads\/([A-G])-[^/]+\/report\.md$/,            (m) => `threads/${m[1]}`]);
  routes.push([/^research\/study\/taxonomy\.yaml$/,                         'study/taxonomy']);
  routes.push([/^research\/study\/categories\/([^/]+)\/(deep\/q[1-3]-[^/]+\.md|batch\.json)$/, (m) => `study/categories/${m[1]}`]);
  return routes;
}

function makeRepoPathToRoute(pathToRoute) {
  return (repoPath) => {
    const norm = repoPath.replace(/^\/+/, '').replace(/\\/g, '/');
    for (const [re, out] of pathToRoute) {
      const m = norm.match(re);
      if (m) return typeof out === 'function' ? out(m) : out;
    }
    return null;
  };
}

// Module-level holder — set at the start of main() once content is loaded.
let _repoPathToRoute = () => null;

// Resolve a (possibly relative) link within a source-markdown context to a
// repo-path, then to a hash route. Leaves http/mailto/# links alone.
function rewriteLinks(html, sourceRepoPath) {
  const sourceDir = path.posix.dirname(sourceRepoPath);
  return html.replace(/href="([^"]+)"/g, (whole, href) => {
    if (/^(https?:|mailto:|#|data:)/.test(href)) return whole;
    const [rawPath, frag] = href.split('#');
    if (!rawPath) return whole;
    const resolved = path.posix.normalize(path.posix.join(sourceDir, rawPath));
    const route = _repoPathToRoute(resolved);
    if (route) return `href="#/${route}${frag ? '#' + frag : ''}"`;
    return whole;
  });
}

// ─────────────── taxonomy ───────────────
async function loadTaxonomy() {
  const raw = await fs.readFile(path.join(ROOT, 'research/study/taxonomy.yaml'), 'utf8');
  const doc = yaml.load(raw);
  const groups = (doc.groups || []).map(g => ({
    group: g.group,
    display: g.display,
    categories: (g.categories || []).map(c => ({
      slug: c.slug,
      name: c.name,
      short: c.short_description || c.short || '',
    })),
  }));
  const slugToGroup = {};
  for (const g of groups) for (const c of g.categories) slugToGroup[c.slug] = g;
  return {
    meta: { version: doc.version, date: doc.date },
    groups,
    slugToGroup,
  };
}

// ─────────────── scorecard metadata extraction ───────────────
function extractBand(q3Text) {
  const direct = q3Text.match(/\bBand[:\s]+\*{0,2}(Deep[- ]green|Green|Yellow|Orange|Red)\b/i);
  const numMatch = q3Text.match(/\bTotal[^\n]{0,60}?(\d{1,2})\s*\/\s*40/i);
  let band = null;
  if (direct) {
    band = direct[1];
  } else {
    const section = q3Text.match(/##\s*Total\s*(?:and|&)?\s*Band[^\n]*\n([\s\S]*?)(?=\n##|\n*$)/i);
    const hay = section ? section[1] : q3Text;
    const bm = hay.match(/\b(Deep[- ]green|Green|Yellow|Orange|Red)\b/i);
    if (bm) band = bm[1];
  }
  if (band) {
    band = band.toLowerCase().replace(/\s+/g, '-');
    band = band.charAt(0).toUpperCase() + band.slice(1);
  }
  return { total: numMatch ? Number(numMatch[1]) : null, band };
}

function extractExclusivityScore(q2Text) {
  const section = q2Text.match(/##\s*Exclusivity[- ]score[^\n]*\n([\s\S]*?)(?=\n##|\n*$)/i);
  const hay = section ? section[1] : q2Text;
  const m = hay.match(/(?:^|\D)([0-5])(?:\s*\/\s*5)?/);
  return m ? Number(m[1]) : null;
}

function extractValuePerLabYear(batchJson) {
  const b17 = batchJson?.answers?.B17?.your_response;
  if (b17 == null) return null;
  if (typeof b17 === 'number') return '$' + b17.toLocaleString();
  if (typeof b17 === 'object' && b17.median != null) {
    return '$' + Number(b17.median).toLocaleString();
  }
  if (typeof b17 === 'object' && b17.low != null && b17.high != null) {
    return `$${Number(b17.low).toLocaleString()}–$${Number(b17.high).toLocaleString()}`;
  }
  return null;
}

function computeCompositeFromRaw({ q3Total, exclusivity, b5, b6, b7, b8, b11, b13, b14 }) {
  const parts = [
    { v: q3Total,         max: 40, w: 0.15 },
    { v: exclusivity,     max: 5,  w: 0.20 },
    { v: b5,              max: 5,  w: 0.10 },
    { v: b6,              max: 5,  w: 0.025 },
    { v: b7,              max: 5,  w: 0.025 },
    { v: b8,              max: 5,  w: 0.05 },
    { v: b11,             max: 5,  w: 0.05 },
    { v: b13,             max: 5,  w: 0.05 },
    { v: b14 != null ? 5 - b14 : null, max: 5, w: 0.05 },
  ].filter(p => p.v != null);
  if (!parts.length) return null;
  const num = parts.reduce((s, p) => s + (p.v / p.max) * p.w, 0);
  const den = parts.reduce((s, p) => s + p.w, 0);
  return den > 0 ? Number((num / den).toFixed(3)) : null;
}

// ─────────────── markdown rendering ───────────────

// Break compact "**Label:** foo · **Label:** bar" front-matter lines into
// one-label-per-line without touching normal prose. Two transforms:
//   (1) inside a line, replace " · **Xxx:**" with "<br>\n**Xxx:**"
//   (2) between two consecutive source lines that both start with "**Xxx:**",
//       append "<br>" to the first so they render on separate visual lines
// Skips fenced code blocks. Labels must end in ":" to count.
function breakCompactMetadata(raw) {
  const META_LABEL = /^\*\*[A-Z][^*\n]{1,80}?:\*\*/;
  const META_INLINE = /\s+·\s+(\*\*[A-Z][^*\n]{1,80}?:\*\*)/g;
  const lines = raw.split('\n');
  const out = [];
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*```/.test(line)) { inFence = !inFence; out.push(line); continue; }
    if (inFence) { out.push(line); continue; }
    let transformed = line.replace(META_INLINE, '<br>\n$1');
    const isMeta = META_LABEL.test(line);
    const nextIsMeta = i + 1 < lines.length && META_LABEL.test(lines[i + 1]);
    if (isMeta && nextIsMeta && !/<br>\s*$/.test(transformed)) {
      transformed = transformed.replace(/\s*$/, '<br>');
    }
    out.push(transformed);
  }
  return out.join('\n');
}

async function renderMarkdownFile(repoPath) {
  const raw = await fs.readFile(path.join(ROOT, repoPath), 'utf8');
  const html = md.render(breakCompactMetadata(raw));
  return rewriteLinks(html, repoPath);
}

// ─────────────── arc-page helpers ───────────────

// Prepend a styled "arc header" callout to a rendered page body.
// pos/round/qa/title come from content config; desc is HTML (pre-escaped).
function arcHeaderHtml(pos, round, qa, title, descHtml) {
  const qaClass = qa === 'Q' ? 'qa-q' : 'qa-a';
  const rootClass = qa === 'Q' ? 'arc-header arc-q' : 'arc-header arc-a';
  return `<div class="${rootClass}">
    <div class="arc-header-label">${pos} <span class="arc-sep">·</span> ${round} <span class="arc-sep">·</span> <span class="${qaClass}">${qa}</span> <span class="arc-sep">·</span> ${title}</div>
    <div class="arc-header-desc">${descHtml}</div>
  </div>`;
}

function arcCrumbLabel(pos, round, qa, title) {
  const qaClass = qa === 'Q' ? 'qa-q' : 'qa-a';
  return `${pos} · ${round} · <span class="${qaClass}">${qa}</span> · ${title}`;
}

// ─────────────── sidebar HTML ───────────────
// Build the full sidebar HTML once, at build time, from the content config.
// This is baked into core.enc (encrypted) so the public repo never sees the
// strategic labels. A <!--SCORECARDS_TREE--> placeholder is replaced at
// runtime by the SPA with a dynamically-computed tree derived from the
// scorecard index.
function buildSidebarHtml(content) {
  const c = content;
  const linkA = (href, label, cls = '') =>
    `<a class="${cls}" data-href="${href}" href="#/${href}">${label}</a>`;
  const arcLink = (href, num, round, qa, title) => {
    const qaClass = qa === 'Q' ? 'qa-q' : 'qa-a';
    return `<a class="arc-link" data-href="${href}" href="#/${href}">${num} <span class="arc-sep">·</span> ${round} <span class="arc-sep">·</span> <span class="${qaClass}">${qa}</span> <span class="arc-sep">·</span> ${title}</a>`;
  };
  const sectionLabel = (text, divider = false) =>
    `<div class="section-label${divider ? ' section-divider' : ''}">${text}</div>`;

  const SCORECARDS_PLACEHOLDER = '<!--SCORECARDS_TREE-->';

  const m = c.branding.masthead;
  const masthead = `<div class="masthead">${m.prefix ? `<span class="masthead-prefix">${m.prefix}</span><span class="masthead-sep"> · </span>` : ''}<span class="masthead-title">${m.title}</span><span class="sub">${m.sub}</span></div>`;

  const continueSection = linkA('continue', c.sidebar.continueLabel, 'featured-continue');

  const arcSection = sectionLabel(c.sidebar.superLabels.arc, true) +
    c.arcPages.map(p => arcLink(p.slug, p.pos, p.round, p.qa, p.title)).join('');

  const threadsSection = sectionLabel(c.sidebar.sectionLabels.threads) +
    c.threads.map(t => linkA(`threads/${t.letter}`, t.label)).join('');

  const studyMain = c.studyDocs.filter(d => !d.inMethodologyAudit);
  const studyAudit = c.studyDocs.filter(d => d.inMethodologyAudit);
  const studySection = sectionLabel(c.sidebar.sectionLabels.study) +
    studyMain.map(d => linkA(`study/${d.slug}`, d.sidebarLabel)).join('') +
    `<details><summary>${c.sidebar.sectionLabels.scorecards}</summary><div class="subtree">` +
      linkA('study/scorecards', c.sidebar.sectionLabels.scorecardsInline) +
      SCORECARDS_PLACEHOLDER +
    `</div></details>` +
    `<details><summary>${c.sidebar.sectionLabels.methodologyAudit}</summary><div class="subtree">` +
      studyAudit.map(d => linkA(`study/${d.slug}`, d.title)).join('') +
    `</div></details>`;

  const round2Section = sectionLabel(c.sidebar.sectionLabels.round2) +
    c.round2Docs.map(d => linkA(`round-2/${d.slug}`, d.title)).join('');

  const foundationalSuper = sectionLabel(c.sidebar.superLabels.foundational, true);

  return masthead + continueSection + arcSection + foundationalSuper + threadsSection + studySection + round2Section;
}

// ─────────────── build pages ───────────────
async function buildCorePages(taxonomy, content) {
  const pages = {};

  // ── arc pages ──
  for (const ap of content.arcPages) {
    const body = await renderMarkdownFile(ap.source);
    pages[ap.slug] = {
      title: `${ap.pos} · ${ap.round} · ${ap.qa} · ${ap.title}`,
      crumb: [{ label: arcCrumbLabel(ap.pos, ap.round, ap.qa, ap.title) }],
      html: arcHeaderHtml(ap.pos, ap.round, ap.qa, ap.title, ap.desc) + body,
    };
  }

  // ── threads ──
  const threadsDir = path.join(ROOT, 'research/threads');
  const threadDirs = (await fs.readdir(threadsDir)).filter(n => /^[A-G]-/.test(n)).sort();
  for (const dir of threadDirs) {
    const letter = dir[0];
    const reportPath = `research/threads/${dir}/report.md`;
    if (!(await exists(path.join(ROOT, reportPath)))) continue;
    const threadEntry = content.threads.find(t => t.letter === letter);
    pages[`threads/${letter}`] = {
      title: threadEntry?.label || `Thread ${letter}`,
      crumb: [{ label: content.crumbLabels.threads }, { label: letter }],
      html: await renderMarkdownFile(reportPath),
    };
  }

  // ── study supporting docs ──
  for (const d of content.studyDocs) {
    if (!d.source) continue;
    if (!(await exists(path.join(ROOT, d.source)))) continue;
    pages[`study/${d.slug}`] = {
      title: d.title,
      crumb: [{ label: content.crumbLabels.study, href: 'study/rankings' }, { label: d.title }],
      html: await renderMarkdownFile(d.source),
    };
  }

  // ── round-2 reports ──
  for (const d of content.round2Docs) {
    const src = `research/round-2/${d.slug}.md`;
    if (!(await exists(path.join(ROOT, src)))) continue;
    pages[`round-2/${d.slug}`] = {
      title: d.title,
      crumb: [{ label: content.crumbLabels.round2 }, { label: d.title }],
      html: await renderMarkdownFile(src),
    };
  }

  // ── continue ──
  pages['continue'] = {
    title: content.continuePageTitle,
    crumb: [{ label: content.continuePageCrumb }],
    html: content.continueHtml,
  };

  return pages;
}

// ─────────────── scorecard pages (per-category) ───────────────
function renderBatchTable(batchJson, questionLabels) {
  const rows = [];
  for (let i = 1; i <= 17; i++) {
    const key = `B${i}`;
    const a = batchJson.answers?.[key];
    if (!a) continue;
    let resp = a.your_response;
    if (Array.isArray(resp)) {
      resp = '<ul>' + resp.map(v => `<li>${typeof v === 'object' ? `<code>${escapeHtml(JSON.stringify(v))}</code>` : escapeHtml(String(v))}</li>`).join('') + '</ul>';
    } else if (resp !== null && typeof resp === 'object') {
      resp = `<pre><code>${escapeHtml(JSON.stringify(resp, null, 2))}</code></pre>`;
    } else {
      resp = escapeHtml(String(resp));
    }
    const label = questionLabels[key] || '';
    rows.push(`<tr>
      <td>${key}</td>
      <td><strong>${escapeHtml(label)}</strong>${resp ? '<br>' + resp : ''}</td>
      <td>${escapeHtml(a.reasoning_for_your_response || '')}</td>
      <td class="conf">${a.confidence_in_your_response_percent ?? '—'}%</td>
      <td class="notes">${escapeHtml(a.notes_if_unusual || '')}</td>
    </tr>`);
  }
  return `<table class="batch-table">
    <thead><tr><th>#</th><th>Question / response</th><th>Reasoning</th><th>Conf.</th><th>Notes</th></tr></thead>
    <tbody>${rows.join('')}</tbody>
  </table>
  <details class="batch-raw"><summary>View raw batch.json</summary><pre><code class="language-json">${escapeHtml(JSON.stringify(batchJson, null, 2))}</code></pre></details>`;
}

async function loadBatchLabels() {
  const src = await fs.readFile(path.join(ROOT, 'research/study/questions.md'), 'utf8');
  const labels = {};
  const re = /\*\*(B\d+)\s*[—\-\.:]\s*([^\*\n]+?)\*\*/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    labels[m[1]] = m[2].trim();
  }
  return labels;
}

async function buildScorecardPages(taxonomy, content) {
  const pages = {};
  const index = [];
  const batchLabels = await loadBatchLabels();
  const catsDir = path.join(ROOT, 'research/study/categories');
  const slugs = (await fs.readdir(catsDir)).filter(n => !n.startsWith('.') && n !== 'CLAUDE.md');

  for (const slug of slugs) {
    const slugDir = path.join(catsDir, slug);
    const stat = await fs.stat(slugDir).catch(() => null);
    if (!stat?.isDirectory()) continue;

    const q1Path = `research/study/categories/${slug}/deep/q1-tam.md`;
    const q2Path = `research/study/categories/${slug}/deep/q2-exclusivity.md`;
    const q3Path = `research/study/categories/${slug}/deep/q3-encroachment.md`;
    const batchPath = `research/study/categories/${slug}/batch.json`;

    const [q1Raw, q2Raw, q3Raw, batchRaw] = await Promise.all([
      readIfExists(path.join(ROOT, q1Path)),
      readIfExists(path.join(ROOT, q2Path)),
      readIfExists(path.join(ROOT, q3Path)),
      readIfExists(path.join(ROOT, batchPath)),
    ]);

    const q1 = q1Raw ? rewriteLinks(md.render(breakCompactMetadata(q1Raw)), q1Path) : '<p><em>Not available.</em></p>';
    const q2 = q2Raw ? rewriteLinks(md.render(breakCompactMetadata(q2Raw)), q2Path) : '<p><em>Not available.</em></p>';
    const q3 = q3Raw ? rewriteLinks(md.render(breakCompactMetadata(q3Raw)), q3Path) : '<p><em>Not available.</em></p>';

    let batchTable = '<p><em>Not available.</em></p>';
    let batchJson = null;
    if (batchRaw) {
      try {
        batchJson = JSON.parse(batchRaw);
        batchTable = renderBatchTable(batchJson, batchLabels);
      } catch (e) {
        batchTable = `<p><em>batch.json parse error: ${escapeHtml(e.message)}</em></p>`;
      }
    }

    const group = taxonomy.slugToGroup[slug];
    const displayName = group?.categories.find(c => c.slug === slug)?.name || slug;
    const shortDesc = group?.categories.find(c => c.slug === slug)?.short || '';

    pages[`study/categories/${slug}`] = {
      title: displayName,
      crumb: [
        { label: content.crumbLabels.study, href: 'study/rankings' },
        { label: content.crumbLabels.scorecards, href: 'study/scorecards' },
        { label: displayName },
      ],
      html: `
        <h1>${escapeHtml(displayName)}</h1>
        <p style="color:var(--ink-soft); font-style:italic; margin-top:-0.6em;">Group: ${escapeHtml(group?.display || 'unknown')}${shortDesc ? ` · ${escapeHtml(shortDesc)}` : ''}</p>
        <h2>§1. TAM &amp; buyer segments</h2>
        ${q1}
        <h2>§2. Data exclusivity</h2>
        ${q2}
        <h2>§3. Frontier-lab encroachment</h2>
        ${q3}
        <h2>§4. Batch scorecard (17 questions)</h2>
        ${batchTable}
      `,
    };

    const { total: q3Total, band } = q3Raw ? extractBand(q3Raw) : { total: null, band: null };
    const exclusivity = q2Raw ? extractExclusivityScore(q2Raw) : null;
    const b5 = batchJson?.answers?.B5?.your_response;
    const b6 = batchJson?.answers?.B6?.your_response;
    const b7 = batchJson?.answers?.B7?.your_response;
    const b8 = batchJson?.answers?.B8?.your_response;
    const b11 = batchJson?.answers?.B11?.your_response;
    const b13 = batchJson?.answers?.B13?.your_response;
    const b14 = batchJson?.answers?.B14?.your_response;
    const asNum = (v) => (typeof v === 'number' ? v : (typeof v === 'object' && v?.score != null ? v.score : null));
    const composite = computeCompositeFromRaw({
      q3Total, exclusivity,
      b5: asNum(b5), b6: asNum(b6), b7: asNum(b7), b8: asNum(b8),
      b11: asNum(b11), b13: asNum(b13), b14: asNum(b14),
    });
    index.push({
      slug,
      name: displayName,
      group_display: group?.display || '—',
      composite,
      band,
      exclusivity,
      value_per_lab_year: extractValuePerLabYear(batchJson),
    });
  }

  return { pages, index };
}

// ─────────────── encryption ───────────────
async function encrypt(jsonObj, password) {
  const text = JSON.stringify(jsonObj);
  const gz = await gzip(Buffer.from(text, 'utf8'), { level: 9 });
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(gz), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    blob: Buffer.concat([encrypted, tag]),
    meta: {
      salt: Array.from(salt),
      iv: Array.from(iv),
      iterations: PBKDF2_ITERATIONS,
      algorithm: 'AES-GCM-256+PBKDF2-SHA256+gzip',
    },
    raw_bytes: text.length,
    compressed_bytes: gz.length,
  };
}

async function writeEncrypted(name, obj) {
  const { blob, meta, raw_bytes, compressed_bytes } = await encrypt(obj, PASSWORD);
  await fs.writeFile(path.join(HERE, `${name}.enc`), blob);
  await fs.writeFile(path.join(HERE, `${name}.meta.json`), JSON.stringify(meta));
  return { raw_bytes, compressed_bytes, encrypted_bytes: blob.length };
}

function encryptBytes(bytes, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(bytes), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    blob: Buffer.concat([encrypted, tag]),
    meta: {
      salt: Array.from(salt),
      iv: Array.from(iv),
      iterations: PBKDF2_ITERATIONS,
      algorithm: 'AES-GCM-256+PBKDF2-SHA256',
    },
  };
}

// Build an encrypted zip of the research corpus that recipients can unpack
// and run in their own Claude Code session. Zip filename and inner dir name
// come from content config.
async function buildZipBundle(content) {
  const stagingRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'bundle-'));
  const stagingDir = path.join(stagingRoot, content.zipStagingDirName);

  const EXCLUDE_REL_PATHS = new Set([
    'website',
    '.claude',
    'meta/raw_brief.md',
    'meta/my_new_notes.txt',
  ]);
  const EXCLUDE_BASENAMES = new Set(['node_modules', '.DS_Store', '.git', '.gitignore', '.claude']);

  await fs.cp(ROOT, stagingDir, {
    recursive: true,
    filter: (src) => {
      const rel = path.relative(ROOT, src).split(path.sep).join('/');
      if (EXCLUDE_REL_PATHS.has(rel)) return false;
      if (EXCLUDE_BASENAMES.has(path.basename(src))) return false;
      if (rel.startsWith('research/') && path.basename(src).startsWith('_')) return false;
      return true;
    },
  });

  // Write the README (content loaded from config, SITE_URL substituted).
  const readmeText = content.zipReadme.replace(/\{\{SITE_URL\}\}/g, SITE_URL);
  await fs.writeFile(path.join(stagingDir, 'README.md'), readmeText);

  const zipPath = path.join(stagingRoot, content.zipFilename);
  await execFileAsync('zip', ['-r', '-X', '-q', zipPath, content.zipStagingDirName], { cwd: stagingRoot });

  const zipBytes = await fs.readFile(zipPath);
  const { blob, meta } = encryptBytes(zipBytes, PASSWORD);
  meta.filename = content.zipFilename;
  meta.uncompressed_size = zipBytes.length;

  await fs.writeFile(path.join(HERE, 'bundle.enc'), blob);
  await fs.writeFile(path.join(HERE, 'bundle.meta.json'), JSON.stringify(meta));

  await fs.rm(stagingRoot, { recursive: true, force: true });

  return { zip_bytes: zipBytes.length, encrypted_bytes: blob.length };
}

// ─────────────── main ───────────────
async function main() {
  const t0 = Date.now();

  process.stdout.write('⟫ loading content config...\n');
  const content = await loadContent();
  _repoPathToRoute = makeRepoPathToRoute(buildPathToRoute(content));

  process.stdout.write('⟫ loading taxonomy...\n');
  const taxonomy = await loadTaxonomy();

  process.stdout.write('⟫ building core pages...\n');
  const corePages = await buildCorePages(taxonomy, content);

  process.stdout.write('⟫ building scorecard pages (101 categories)...\n');
  const { pages: scorecardPages, index: scorecardIndex } = await buildScorecardPages(taxonomy, content);

  scorecardIndex.sort((a, b) => (b.composite ?? -1) - (a.composite ?? -1));

  process.stdout.write('⟫ building sidebar HTML...\n');
  const sidebarHtml = buildSidebarHtml(content);

  const core = {
    version: 1,
    built_at: new Date().toISOString(),
    pages: corePages,
    taxonomyGroups: taxonomy.groups,
    taxonomyMeta: taxonomy.meta,
    scorecardIndex,
    sidebarHtml,
    views: content.views,
  };
  const scorecards = {
    version: 1,
    pages: scorecardPages,
  };

  process.stdout.write('⟫ encrypting core bundle...\n');
  const coreStats = await writeEncrypted('core', core);
  process.stdout.write('⟫ encrypting scorecards bundle...\n');
  const scStats = await writeEncrypted('scorecards', scorecards);
  process.stdout.write('⟫ building & encrypting takeaway zip bundle...\n');
  const zipStats = await buildZipBundle(content);

  const ms = Date.now() - t0;
  const kb = (n) => (n / 1024).toFixed(1) + ' KB';
  console.log(`\nDone in ${ms}ms.`);
  console.log(`  core.enc       : ${kb(coreStats.encrypted_bytes)} (from ${kb(coreStats.raw_bytes)} raw, ${kb(coreStats.compressed_bytes)} gzipped)`);
  console.log(`  scorecards.enc : ${kb(scStats.encrypted_bytes)} (from ${kb(scStats.raw_bytes)} raw, ${kb(scStats.compressed_bytes)} gzipped)`);
  console.log(`  bundle.enc     : ${kb(zipStats.encrypted_bytes)} (zip: ${kb(zipStats.zip_bytes)})`);
  console.log(`  password       : ${PASSWORD.replace(/./g, '•')} (${PASSWORD.length} chars)`);
  console.log(`  pages          : core=${Object.keys(corePages).length}, scorecards=${Object.keys(scorecardPages).length}`);
}

main().catch(e => { console.error(e); process.exit(1); });
