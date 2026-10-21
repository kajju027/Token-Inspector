'use strict';

/* ------------------------------------------------------------------ state */
const STATE = {
  results: [],
  filter: 'all',
  zone: 'Asia/Kolkata',
  theme: 'dark',
  sessionRemaining: 0,
  sessionTimer: null,
  clockTimer: null,
  installPrompt: null,
  toastTimer: null,
  sessionSync: null,
};
const KEY_ZONE = 'ti.timezone';
const KEY_THEME = 'ti.theme';
const EXPIRING_WINDOW = 24 * 3600;
const EXAMPLE_URL =
  'https://dai-fancode.pages.dev/mumbai/4249615_english_hls_d47039c54e87886_1ta-di_h264/index.m3u8';

const $ = (id) => document.getElementById(id);
const val = (id) => ($(id) ? $(id).value : '');
const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

/* ------------------------------------------------------------------ helpers */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function svgIcon(paths, viewBox) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', viewBox || '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  paths.forEach(([tag, attrs]) => {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    svg.appendChild(node);
  });
  return svg;
}
function safeZone(value) {
  try {
    new Intl.DateTimeFormat('en-GB', { timeZone: value });
    return value;
  } catch {
    return 'Asia/Kolkata';
  }
}
function timeText(epoch, options) {
  if (!epoch) return 'Not published';
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: STATE.zone,
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      ...options,
    }).format(new Date(epoch * 1000));
  } catch {
    return 'Invalid date';
  }
}
function shortTime(epoch) {
  if (!epoch) return '';
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: STATE.zone,
      day: '2-digit',
      month: 'short',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(new Date(epoch * 1000));
  } catch {
    return '';
  }
}
function durationText(seconds) {
  const total = Math.abs(Math.round(seconds));
  if (total < 60) return `${total}s`;
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${String(minutes).padStart(2, '0')}m`;
  return `${minutes}m ${String(secs).padStart(2, '0')}s`;
}
function relativeText(epoch) {
  const delta = epoch - Math.floor(Date.now() / 1000);
  const label = durationText(delta);
  return delta >= 0 ? `in ${label}` : `${label} ago`;
}
function bytesText(bytes) {
  if (!bytes && bytes !== 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
function numberText(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return new Intl.NumberFormat('en-US').format(value);
}
function statusOf(result) {
  if (!result.expires) return { key: 'unknown', label: 'No token' };
  const diff = result.expires - Math.floor(Date.now() / 1000);
  if (diff <= 0) return { key: 'expired', label: 'Expired' };
  if (diff <= EXPIRING_WINDOW) return { key: 'expiring', label: 'Expiring soon' };
  return { key: 'valid', label: 'Active' };
}
function toast(message) {
  const node = $('toast');
  if (!node) return;
  node.textContent = message;
  node.classList.add('show');
  clearTimeout(STATE.toastTimer);
  STATE.toastTimer = setTimeout(() => node.classList.remove('show'), 2600);
}
async function copyText(value, message) {
  try {
    await navigator.clipboard.writeText(String(value));
    toast(message || 'Copied');
  } catch {
    toast('Clipboard permission is unavailable in this browser');
  }
}
function copyButton(value, label) {
  const button = el('button', 'copy-btn', label || 'copy');
  button.type = 'button';
  button.addEventListener('click', () => copyText(value, 'Copied to clipboard'));
  return button;
}

/* --------------------------------------------------------------- busy states */
const CHECK_GLYPH =
  '<svg class="check-glyph" viewBox="0 0 20 20" aria-hidden="true"><path d="m4.4 10.6 3.7 3.6 7.5-7.6"/></svg>';
const DOTS_GLYPH =
  '<span class="dot-wave" aria-hidden="true"><span></span><span></span><span></span></span>';

function labelTarget(button) {
  return button.querySelector('.button-label') || button;
}
function beginBusy(button, text) {
  if (!button || button.dataset.busy === '1') return false;
  const target = labelTarget(button);
  button.dataset.idle = target.innerHTML;
  button.dataset.busy = '1';
  button.dataset.busyAt = String(Date.now());
  button.disabled = true;
  button.classList.remove('success');
  button.classList.add('is-loading');
  target.innerHTML = `${text || 'WORKING'}${DOTS_GLYPH}`;
  return true;
}
function finishBusy(button, text, hold) {
  if (!button || button.dataset.busy !== '1') return Promise.resolve();
  const elapsed = Date.now() - Number(button.dataset.busyAt || 0);
  const minimum = 420 - elapsed;
  return new Promise((resolve) => {
    setTimeout(() => {
      button.classList.remove('is-loading');
      button.classList.add('success');
      labelTarget(button).innerHTML = `${CHECK_GLYPH}${text || 'DONE'}`;
      delete button.dataset.busyAt;
      setTimeout(() => resetBusy(button), hold || 900);
      resolve();
    }, Math.max(0, minimum));
  });
}
function resetBusy(button) {
  if (!button || button.dataset.busy !== '1') return;
  labelTarget(button).innerHTML = button.dataset.idle || '';
  button.classList.remove('success', 'is-loading');
  button.disabled = false;
  delete button.dataset.busy;
  delete button.dataset.idle;
}

/* ------------------------------------------------------------------ modals */
function openModal(id) {
  const node = $(id);
  if (!node) return;
  node.hidden = false;
  const focusable = node.querySelector('button, [href], input, select, summary');
  if (focusable) setTimeout(() => focusable.focus({ preventScroll: true }), 60);
}
function closeModal(id) {
  const node = $(id);
  if (node) node.hidden = true;
}
function closeModals() {
  ['guideModal', 'accessModal', 'settingsModal'].forEach(closeModal);
}

/* ------------------------------------------------------------------- theme */
function applyTheme(choice) {
  STATE.theme = ['dark', 'light', 'system'].includes(choice) ? choice : 'dark';
  const resolved =
    STATE.theme === 'system'
      ? window.matchMedia('(prefers-color-scheme: light)').matches
        ? 'light'
        : 'dark'
      : STATE.theme;
  document.documentElement.dataset.theme = resolved;
  localStorage.setItem(KEY_THEME, STATE.theme);
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', resolved === 'light' ? '#eef1f5' : '#070a0e');
  const label = $('themeLabel');
  if (label) label.textContent = resolved === 'light' ? 'LIGHT' : 'DARK';
  const toggle = $('themeButton');
  if (toggle) {
    toggle.setAttribute('aria-label', `Switch to ${resolved === 'light' ? 'dark' : 'light'} theme`);
    toggle.title = `Switch to ${resolved === 'light' ? 'dark' : 'light'} theme`;
  }
  document.querySelectorAll('[data-theme-choice]').forEach((button) => {
    button.classList.toggle('is-active', button.dataset.themeChoice === STATE.theme);
  });
}
function toggleTheme() {
  const current = document.documentElement.dataset.theme;
  applyTheme(current === 'light' ? 'dark' : 'light');
}

/* -------------------------------------------------------------------- auth */
function setScreen(mode) {
  const overlay = $('accessOverlay');
  if (!mode) {
    overlay.classList.add('is-hidden');
    return;
  }
  overlay.classList.remove('is-hidden');
  $('bootCard').hidden = mode !== 'boot';
  $('authCard').hidden = mode !== 'auth';
}
function setLocked(locked, mode) {
  $('appShell').classList.toggle('is-locked', locked);
  $('appShell').setAttribute('aria-hidden', String(locked));
  if (locked) {
    setScreen(mode || 'auth');
    if ((mode || 'auth') === 'auth') setTimeout(() => $('passwordInput').focus(), 90);
  } else {
    setScreen(null);
  }
}
function sessionClock(seconds) {
  const minutes = String(Math.floor(seconds / 60)).padStart(2, '0');
  const secs = String(seconds % 60).padStart(2, '0');
  return `${minutes}:${secs}`;
}
function startSessionTimer(seconds) {
  STATE.sessionRemaining = seconds;
  clearInterval(STATE.sessionTimer);
  const tick = () => {
    STATE.sessionRemaining = Math.max(0, STATE.sessionRemaining - 1);
    const clock = sessionClock(STATE.sessionRemaining);
    $('footerSession').textContent = clock;
    $('sessionLabel').textContent = `SESSION ${clock}`;
    $('sessionPill').classList.add('is-live');
    if (STATE.sessionRemaining === 0) {
      clearInterval(STATE.sessionTimer);
      $('sessionPill').classList.remove('is-live');
      $('passwordInput').value = '';
      setLocked(true, 'auth');
      $('loginError').textContent = 'Session ended. Enter your passkey to continue.';
    }
  };
  tick();
  STATE.sessionTimer = setInterval(tick, 1000);
}
async function syncSession() {
  try {
    const response = await fetch('/api/session', { cache: 'no-store' });
    const data = await response.json();
    if (data.authenticated) {
      STATE.sessionRemaining = data.remaining;
      $('sessionPill').classList.add('is-live');
      return true;
    }
    $('sessionPill').classList.remove('is-live');
    setLocked(true, 'auth');
    return false;
  } catch {
    return false;
  }
}
async function refreshSession() {
  const bootAt = Date.now();
  setLocked(true, 'boot');
  const holdBoot = async () => {
    const left = 520 - (Date.now() - bootAt);
    if (left > 0) await new Promise((resolve) => setTimeout(resolve, left));
  };
  try {
    const response = await fetch('/api/session', { cache: 'no-store' });
    const data = await response.json();
    if (data.authenticated) {
      await holdBoot();
      setLocked(false);
      startSessionTimer(data.remaining);
      return;
    }
    await holdBoot();
    setLocked(true, 'auth');
    if (!data.configured) {
      $('loginError').textContent =
        'Access is not configured yet. Set MASTER_PASSWORD on the server.';
      $('loginButton').disabled = true;
    }
  } catch {
    setLocked(true, 'auth');
    $('loginError').textContent = 'Cannot reach the service. Check your connection.';
  }
}

/* ---------------------------------------------------------------- rendering */
function factBox(label, value) {
  const box = el('div', 'fact');
  box.append(el('div', 'fact-label', label), el('div', 'fact-value', value));
  return box;
}

function badgeFor(result) {
  const status = statusOf(result);
  return el('span', `badge ${status.key}`, status.label);
}

function timelineBlock(result) {
  const status = statusOf(result);
  const now = Math.floor(Date.now() / 1000);
  const block = el('div', 'timeline-block');
  const row = el('div', 'timeline-times');

  const startCell = el('div', 'tl-cell');
  startCell.append(el('div', 'tl-label', 'Token created'));
  const startValue = el('div', `tl-value${result.generated ? '' : ' na'}`,
    result.generated ? timeText(result.generated) : 'Not published');
  startCell.append(startValue);
  startCell.append(el('div', 'tl-sub',
    result.generated ? `unix ${result.generated}` : 'the link carries no start field'));

  const ttlCell = el('div', 'tl-ttl');
  const ttlValue = el('span', 'ttl-value');
  ttlValue.dataset.expires = String(result.expires || '');
  ttlValue.textContent = result.expires
    ? (result.expires > now ? durationText(result.expires - now) : 'expired')
    : '—';
  ttlValue.dataset.state = status.key;
  ttlCell.append(ttlValue, el('span', 'ttl-caption',
    result.expires ? 'time left' : 'no expiry'));

  const endCell = el('div', 'tl-cell end');
  endCell.append(el('div', 'tl-label', 'Token expires'));
  endCell.append(el('div', `tl-value${result.expires ? '' : ' na'}`,
    result.expires ? timeText(result.expires) : 'Not published'));
  endCell.append(el('div', 'tl-sub',
    result.expires ? `unix ${result.expires} · ${relativeText(result.expires)}` : 'no numeric expiry found'));

  row.append(startCell, ttlCell, endCell);
  block.append(row);

  const track = el('div', 'tl-track');
  const fill = el('div', `tl-fill ${status.key}`);
  let percent = 0;
  if (result.expires && result.generated && result.expires > result.generated) {
    percent = clamp(((now - result.generated) / (result.expires - result.generated)) * 100, 0, 100);
  } else if (result.expires && status.key === 'valid') {
    percent = 100;
  } else if (status.key === 'expired') {
    percent = 100;
  }
  fill.dataset.target = String(percent);
  track.append(fill);
  block.append(track);

  const scale = el('div', 'tl-scale');
  scale.append(
    el('span', '', result.generated ? shortTime(result.generated) : 'start unknown'),
    el('span', '', result.expires ? shortTime(result.expires) : 'expiry unknown')
  );
  block.append(scale);
  return block;
}

function tokensPane(result) {
  const body = el('div', 'pane-body');
  const tokens = result.tokens || [];
  if (!tokens.length) {
    body.append(el('p', 'empty-note',
      result.kind === 'note'
        ? result.notes?.[0] || 'Nothing to inspect.'
        : 'No start time, expiry or lifetime field was found in the link, its response headers or the manifest body.'));
  } else {
    const wrap = el('div', 'table-wrap');
    const table = el('table');
    const thead = el('thead');
    const headRow = el('tr');
    ['Field', 'Meaning', 'Value', 'Decoded time', 'Found in'].forEach((label) =>
      headRow.append(el('th', '', label)));
    thead.append(headRow);
    const tbody = el('tbody');
    tokens.forEach((token) => {
      const row = el('tr');
      const field = el('td');
      field.append(el('span', 'tag accent', token.field));
      const meaning = el('td');
      const kindLabels = { expires: 'Expiry', generated: 'Start / generated', lifetime: 'Lifetime', signature: 'Signature' };
      meaning.append(el('span', `tag ${token.kind === 'expires' ? 'rose' : token.kind === 'generated' ? 'green' : 'muted'}`,
        kindLabels[token.kind] || token.kind));
      const valueCell = el('td', 'cell-mono');
      valueCell.append(el('span', '', token.kind === 'lifetime' ? `${numberText(token.value)} s` : numberText(token.value)));
      valueCell.append(copyButton(token.value, 'copy'));
      const decoded = el('td', 'cell-mono');
      if (token.kind === 'lifetime') {
        decoded.textContent = `${durationText(token.value)} window`;
      } else {
        decoded.textContent = timeText(token.value);
      }
      const origin = el('td', 'cell-muted');
      origin.textContent = token.origin || '—';
      if (token.note) origin.append(el('div', 'cell-muted', token.note));
      row.append(field, meaning, valueCell, decoded, origin);
      tbody.append(row);
    });
    table.append(thead, tbody);
    wrap.append(table);
    body.append(wrap);
  }
  const notes = (result.notes || []).filter(Boolean);
  if (notes.length) {
    const list = el('div', 'notes');
    notes.forEach((note) => list.append(el('div', `note ${/fail|block|cannot|not reach|exceed/i.test(note) ? 'warn' : ''}`, note)));
    body.append(list);
  }
  return body;
}

function anatomyPane(result) {
  const body = el('div', 'pane-body');
  const url = result.url;
  if (!url) {
    body.append(el('p', 'empty-note', 'This input is not a URL, so there is no link anatomy to show.'));
    return body;
  }
  const anatomy = el('div', 'anatomy');

  const hostBlock = el('div', 'anatomy-block');
  hostBlock.append(el('header', '', 'Host & scheme'));
  const hostBody = el('div');
  const hostLine = el('div', 'host-line');
  hostLine.append(
    el('span', 'scheme', `${url.scheme}://`),
    el('span', 'host', url.host || ''),
    el('span', 'port', url.port ? `:${url.port}` : ''),
    el('span', 'cell-muted', url.extension ? `.${url.extension}` : ''),
    el('span', 'tag muted', url.signed ? 'signed link' : 'no token in link')
  );
  hostBody.append(hostLine);
  hostBlock.append(hostBody);
  anatomy.append(hostBlock);

  const pathBlock = el('div', 'anatomy-block');
  pathBlock.append(el('header', '', `Path · ${url.segments.length} segment${url.segments.length === 1 ? '' : 's'}`));
  const pathBody = el('div');
  const list = el('div', 'segment-list');
  if (!url.segments.length) {
    pathBody.append(el('p', 'empty-note', 'Root path.'));
  } else {
    url.segments.forEach((segment) => {
      const chip = el('span', `segment ${segment.kind}`, segment.value);
      chip.title = segment.kind;
      chip.append(el('span', 'seg-kind', segment.kind));
      list.append(chip);
    });
    pathBody.append(list);
  }
  pathBlock.append(pathBody);
  const legend = el('div', 'legend');
  ['manifest', 'media', 'hash', 'token', 'path'].forEach((kind) => {
    const item = el('span');
    item.append(el('i', kind), document.createTextNode(kind));
    legend.append(item);
  });
  pathBlock.append(legend);
  anatomy.append(pathBlock);

  const queryBlock = el('div', 'anatomy-block');
  queryBlock.append(el('header', '', `Query · ${url.query.length} field${url.query.length === 1 ? '' : 's'}`));
  const queryBody = el('div');
  if (!url.query.length) {
    queryBody.append(el('p', 'empty-note',
      'This link has no query string. Expiry and start values can still exist inside the manifest body — check the Overview and Source tabs.'));
  } else {
    const wrap = el('div', 'table-wrap');
    wrap.style.border = '0';
    const table = el('table');
    table.style.minWidth = '420px';
    const thead = el('thead');
    const headRow = el('tr');
    ['Field', 'Type', 'Value', ''].forEach((label) => headRow.append(el('th', '', label)));
    thead.append(headRow);
    const tbody = el('tbody');
    url.query.forEach((param) => {
      const row = el('tr');
      const key = el('td', 'cell-mono');
      key.textContent = param.key;
      const type = el('td');
      type.append(el('span', `tag ${param.kind === 'expires' ? 'rose' : param.kind === 'generated' ? 'green' : param.kind === 'signature' ? 'muted' : 'accent'}`,
        param.kind));
      const value = el('td', 'cell-mono');
      value.textContent = param.value;
      if (param.epoch) value.append(el('div', 'cell-muted', timeText(param.epoch)));
      if (param.note) value.append(el('div', 'cell-muted', param.note));
      const actions = el('td');
      if (!param.masked) actions.append(copyButton(param.value));
      row.append(key, type, value, actions);
      tbody.append(row);
    });
    table.append(thead, tbody);
    wrap.append(table);
    queryBody.append(wrap);
  }
  queryBlock.append(queryBody);
  anatomy.append(queryBlock);

  body.append(anatomy);
  return body;
}

function playlistPane(result) {
  const body = el('div', 'pane-body');
  const manifest = result.manifest;
  if (manifest && (manifest.type || manifest.segmentCount)) {
    const facts = el('div', 'fact-grid');
    facts.append(
      factBox('Manifest type', manifest.type || 'unknown'),
      factBox('Segments', manifest.segmentCount ? numberText(manifest.segmentCount) : '—'),
      factBox('Duration', manifest.duration ? `${manifest.duration}s` : '—'),
      factBox('Target duration', manifest.targetDuration ? `${manifest.targetDuration}s` : '—'),
      factBox('Encrypted', manifest.encrypted ? 'yes' : 'no'),
      factBox('Discovered at', manifest.depth ? `depth ${manifest.depth}` : 'entry link')
    );
    body.append(facts);
  }
  const variants = result.variants || [];
  if (!variants.length) {
    body.append(el('p', 'empty-note',
      'No variant or segment link was captured. This usually means the manifest is a media playlist without signed child links, or the remote fetch was blocked.'));
  } else {
    const wrap = el('div', 'table-wrap');
    const table = el('table');
    const thead = el('thead');
    const headRow = el('tr');
    ['Quality', 'Resolution', 'Bitrate', 'Codecs', 'Signed link', 'Expires', 'Status'].forEach((label) =>
      headRow.append(el('th', '', label)));
    thead.append(headRow);
    const tbody = el('tbody');
    variants.forEach((variant) => {
      const row = el('tr');
      const quality = el('td');
      quality.append(el('span', 'tag accent', variant.label || 'Variant'));
      row.append(quality);
      row.append(el('td', 'cell-mono', variant.resolution || '—'));
      row.append(el('td', 'cell-mono', variant.bandwidth ? `${Math.round(variant.bandwidth / 1000)} kbps` : '—'));
      row.append(el('td', 'cell-mono cell-muted', variant.codecs || '—'));
      const link = el('td', 'cell-url');
      link.textContent = variant.url || '—';
      row.append(link);
      const expires = el('td', 'cell-num');
      if (variant.expires) {
        expires.textContent = timeText(variant.expires);
        if (variant.generated) expires.append(el('div', 'cell-muted', `${durationText(variant.expires - variant.generated)} lifetime`));
      } else {
        expires.textContent = 'no token';
        expires.classList.add('cell-muted');
      }
      const status = el('td');
      const key = !variant.expires
        ? 'unknown'
        : variant.expires < Math.floor(Date.now() / 1000)
          ? 'expired'
          : variant.expires - Math.floor(Date.now() / 1000) <= EXPIRING_WINDOW
            ? 'expiring'
            : 'valid';
      status.append(el('span', `tag ${key === 'valid' ? 'green' : key === 'expired' ? 'rose' : key === 'expiring' ? 'amber' : 'muted'}`,
        key === 'valid' ? 'active' : key === 'expired' ? 'expired' : key === 'expiring' ? 'expiring' : 'no token'));
      row.append(status);
      tbody.append(row);
    });
    table.append(thead, tbody);
    wrap.append(table);
    body.append(wrap);
  }
  return body;
}

function requestsPane(result) {
  const body = el('div', 'pane-body');
  const requests = result.requests || [];
  if (!requests.length) {
    body.append(el('p', 'empty-note', 'No remote request was made for this entry.'));
    return body;
  }
  const list = el('div', 'request-list');
  requests.forEach((request) => {
    const item = el('div', 'request');
    const depth = el('span', 'request-depth', `L${request.depth}`);
    const info = el('div', 'request-body');
    info.append(el('div', 'request-url', request.url));
    info.append(el('div', 'request-label',
      `${request.label || 'manifest'}${request.redirects ? ` · ${request.redirects} redirect(s)` : ''}${request.error ? ` · ${request.error}` : ''}`));
    const meta = el('div', 'request-meta');
    meta.append(
      el('span', '', request.status ? `HTTP ${request.status}` : 'failed'),
      el('span', '', bytesText(request.bytes)),
      el('span', '', request.contentType || 'unknown type')
    );
    item.append(depth, info, meta);
    list.append(item);
  });
  body.append(list);
  return body;
}

function sourcePane(result) {
  const body = el('div', 'pane-body');
  const excerpts = result.excerpts || [];
  if (!excerpts.length) {
    body.append(el('p', 'empty-note', 'No source was captured for this entry.'));
    return body;
  }
  excerpts.forEach((excerpt) => {
    const block = el('div', 'anatomy-block');
    block.append(el('header', '', excerpt.url || 'source'));
    const pre = el('pre', 'source', excerpt.text || '');
    const holder = el('div');
    holder.style.padding = '0';
    holder.append(pre);
    block.append(holder);
    body.append(block);
    body.append(el('p', 'note', 'Signature, hmac and token values are replaced before the source reaches your browser.'));
  });
  return body;
}

function buildTabs(result) {
  const tabs = el('nav', 'tabs');
  tabs.setAttribute('role', 'tablist');
  const variants = (result.variants || []).length;
  const requests = (result.requests || []).length;
  const definitions = [
    ['overview', 'Overview', (result.tokens || []).length],
    ['anatomy', 'URL anatomy', 0],
    ['playlist', 'Manifest', variants],
    ['requests', 'Requests', requests],
    ['source', 'Source', 0],
  ];
  definitions.forEach(([key, label, count], index) => {
    const button = el('button', `tab${index === 0 ? ' is-active' : ''}`, label);
    button.type = 'button';
    button.setAttribute('role', 'tab');
    button.dataset.tab = key;
    button.setAttribute('aria-selected', index === 0 ? 'true' : 'false');
    if (count) button.append(el('span', 'tab-count', String(count)));
    tabs.append(button);
  });
  return tabs;
}

function buildPane(result, key) {
  const pane = el('div', 'pane');
  pane.dataset.pane = key;
  let content;
  if (key === 'anatomy') content = anatomyPane(result);
  else if (key === 'playlist') content = playlistPane(result);
  else if (key === 'requests') content = requestsPane(result);
  else if (key === 'source') content = sourcePane(result);
  else content = tokensPane(result);
  pane.append(content);
  return pane;
}

function renderCard(result, index) {
  const card = el('article', 'card');
  card.dataset.status = statusOf(result).key;

  const head = el('header', 'card-head');
  head.append(el('span', 'card-index', String(index + 1).padStart(2, '0')));
  const title = el('div', 'card-title');
  title.append(el('h3', '', result.displayInput || result.input || 'Pasted input'));
  const meta = el('div', 'card-meta');
  const metaParts = [];
  if (result.url) metaParts.push(result.url.host);
  metaParts.push(result.kind === 'manifest' ? 'pasted manifest' : result.kind === 'text' ? 'pasted text' : result.url?.extension || 'link');
  metaParts.push(`${(result.requests || []).length} request${(result.requests || []).length === 1 ? '' : 's'}`);
  metaParts.push(`${(result.tokens || []).length} token field${(result.tokens || []).length === 1 ? '' : 's'}`);
  metaParts.push(`${(result.variants || []).length} signed link${(result.variants || []).length === 1 ? '' : 's'}`);
  metaParts.forEach((part, position) => {
    const span = el('span', '', part);
    if (position) span.prepend(el('i'));
    meta.append(span);
  });
  title.append(meta);
  head.append(title, badgeFor(result));
  card.append(head);

  card.append(timelineBlock(result));

  const tabs = buildTabs(result);
  card.append(tabs);
  const panes = ['overview', 'anatomy', 'playlist', 'requests', 'source'];
  panes.forEach((key) => card.append(buildPane(result, key)));
  card.querySelectorAll('[data-pane]').forEach((pane, position) => {
    if (position > 0) pane.hidden = true;
  });

  tabs.addEventListener('click', (event) => {
    const button = event.target.closest('.tab');
    if (!button) return;
    tabs.querySelectorAll('.tab').forEach((tab) => {
      tab.classList.toggle('is-active', tab === button);
      tab.setAttribute('aria-selected', String(tab === button));
    });
    card.querySelectorAll('[data-pane]').forEach((pane) => {
      pane.hidden = pane.dataset.pane !== button.dataset.tab;
    });
  });

  const foot = el('footer', 'card-foot');
  const group = el('div', 'foot-group');
  if (result.expires && result.generated && result.expires > result.generated) {
    group.append(el('span', '', `Validity window ${durationText(result.expires - result.generated)}`));
  }
  if (result.tokens?.some((token) => token.kind === 'lifetime')) {
    group.append(el('span', '', 'Lifetime-based token'));
  }
  group.append(el('span', '', `Times in ${STATE.zone}`));
  foot.append(group);
  const tools = el('div', 'foot-group');
  if (result.displayInput && result.displayInput !== 'Pasted text / cookie string') {
    tools.append(copyButton(result.displayInput, 'copy link'));
  }
  foot.append(tools);
  card.append(foot);

  if (result.kind === 'note') {
    card.querySelector('.timeline-block')?.remove();
    card.querySelectorAll('[data-pane]').forEach((pane) => {
      if (pane.dataset.pane !== 'overview') pane.remove();
    });
  }
  return card;
}

function renderSummary() {
  const counts = { all: STATE.results.length, valid: 0, expiring: 0, expired: 0, unknown: 0 };
  let signed = 0;
  STATE.results.forEach((result) => {
    counts[statusOf(result).key] += 1;
    signed += (result.variants || []).length;
  });

  const grid = $('summaryRow');
  grid.replaceChildren();
  const definitions = [
    ['Sources', counts.all, ''],
    ['Signed links', signed, 'is-accent'],
    ['Active', counts.valid, 'is-green'],
    ['Expiring', counts.expiring, 'is-amber'],
    ['Expired', counts.expired, 'is-rose'],
    ['No token', counts.unknown, ''],
  ];
  definitions.forEach(([label, value, className]) => {
    const stat = el('div', `stat ${className}`.trim());
    stat.append(el('div', 'stat-label', label), el('div', 'stat-value', numberText(value)));
    grid.append(stat);
  });

  $('resultCount').textContent = `${counts.all} source${counts.all === 1 ? '' : 's'}`;
  document.querySelectorAll('.filter-chip').forEach((chip) => {
    const filter = chip.dataset.filter;
    const count = counts[filter] ?? 0;
    chip.querySelector('span').textContent = String(count);
    chip.disabled = count === 0 && filter !== 'all';
  });
}

function renderList() {
  const list = $('resultsList');
  list.replaceChildren();
  const visible = STATE.results.filter((result) => {
    if (STATE.filter === 'all') return true;
    return statusOf(result).key === STATE.filter;
  });
  if (!visible.length) {
    list.append(el('p', 'empty-note', 'No sources match this filter.'));
    return;
  }
  visible.forEach((result) => list.append(renderCard(result, STATE.results.indexOf(result))));
  requestAnimationFrame(() => {
    list.querySelectorAll('.tl-fill').forEach((fill) => {
      fill.style.width = `${fill.dataset.target || 0}%`;
    });
  });
}

function renderReport() {
  renderSummary();
  renderList();
}

/* -------------------------------------------------------------------- clock */
function tickClock() {
  const now = new Date();
  try {
    $('clockTime').textContent = new Intl.DateTimeFormat('en-GB', {
      timeZone: STATE.zone, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }).format(now);
    $('clockDate').textContent = new Intl.DateTimeFormat('en-GB', {
      timeZone: STATE.zone, weekday: 'long', day: '2-digit', month: 'long',
    }).format(now);
  } catch {
    $('clockTime').textContent = '--:--:--';
  }
  document.querySelectorAll('.ttl-value[data-expires]').forEach((node) => {
    const expires = Number(node.dataset.expires);
    if (!expires) return;
    const diff = expires - Math.floor(Date.now() / 1000);
    node.textContent = diff > 0 ? durationText(diff) : 'expired';
  });
}

/* ------------------------------------------------------------------ actions */
function populateTimezones() {
  const deviceZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  $('clockDevice').textContent = deviceZone;
  $('deviceZoneName').textContent = deviceZone;
  const zones = typeof Intl.supportedValuesOf === 'function'
    ? Intl.supportedValuesOf('timeZone')
    : ['UTC', 'Asia/Kolkata', 'Asia/Dhaka', 'Europe/London', 'Europe/Paris', 'America/New_York', 'America/Los_Angeles', 'Australia/Sydney'];
  const all = Array.from(new Set(['Asia/Kolkata', deviceZone, STATE.zone, ...zones]).values());
  const select = $('timezoneSelect');
  select.replaceChildren();
  all
    .sort((a, b) => (a === 'Asia/Kolkata' ? -1 : b === 'Asia/Kolkata' ? 1 : a.localeCompare(b)))
    .forEach((zone) => {
      const option = document.createElement('option');
      option.value = zone;
      option.textContent = zone === 'Asia/Kolkata'
        ? 'India Standard Time · Asia/Kolkata'
        : zone === deviceZone
          ? `${zone} · device`
          : zone;
      select.append(option);
    });
  select.value = STATE.zone;
}

function changeTimezone(zone) {
  STATE.zone = safeZone(zone);
  localStorage.setItem(KEY_ZONE, STATE.zone);
  $('footerZone').textContent = STATE.zone;
  tickClock();
  if (STATE.results.length) renderReport();
}

async function inspect() {
  const text = val('inputData').trim();
  if (!text) {
    toast('Paste a link or manifest first');
    $('inputData').focus();
    return;
  }
  const button = $('analyzeButton');
  const composer = document.querySelector('.composer');
  beginBusy(button, 'SCANNING');
  composer.classList.add('is-scanning');
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, inspectRemote: $('deepScan').checked }),
    });
    let data = {};
    try {
      data = await response.json();
    } catch {
      data = {};
    }
    if (response.status === 401) {
      setLocked(true);
      throw new Error('Session expired. Unlock again to continue.');
    }
    if (!response.ok) throw new Error(data.error || 'Inspection failed.');
    STATE.results = data.results || [];
    STATE.filter = 'all';
    document.querySelectorAll('.filter-chip').forEach((chip) =>
      chip.classList.toggle('is-active', chip.dataset.filter === 'all'));
    renderReport();
    $('resultsSection').hidden = false;
    await finishBusy(button, 'READY', 700);
    composer.classList.remove('is-scanning');
    $('resultsSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    resetBusy(button);
    composer.classList.remove('is-scanning');
    toast(error.message || 'Could not inspect this source');
  }
}

function reportText() {
  const lines = [];
  STATE.results.forEach((result, index) => {
    const status = statusOf(result);
    lines.push(`SOURCE ${index + 1}: ${result.displayInput || result.input}`);
    if (result.url) lines.push(`Host: ${result.url.host}${result.url.path}`);
    lines.push(`Generated: ${result.generated ? `${timeText(result.generated)} (unix ${result.generated})` : 'N/A'}`);
    lines.push(`Expires: ${result.expires ? `${timeText(result.expires)} (unix ${result.expires})` : 'N/A'}`);
    lines.push(`Status: ${status.label}`);
    if (result.tokens?.length) {
      lines.push('Token fields:');
      result.tokens.forEach((token) => {
        lines.push(`  - ${token.field} (${token.kind}) = ${token.value} · ${token.kind === 'lifetime' ? durationText(token.value) : timeText(token.value)} · ${token.origin || ''}`);
      });
    }
    if (result.variants?.length) {
      lines.push(`Signed links (${result.variants.length}):`);
      result.variants.forEach((variant) => {
        lines.push(`  - ${variant.label} ${variant.resolution || ''} ${variant.url}`);
      });
    }
    if (result.requests?.length) {
      lines.push('Requests:');
      result.requests.forEach((request) => {
        lines.push(`  - L${request.depth} HTTP ${request.status ?? 'failed'} ${bytesText(request.bytes)} ${request.url}`);
      });
    }
    if (result.notes?.length) lines.push(...result.notes.map((note) => `Note: ${note}`));
    lines.push('');
  });
  return lines.join('\n');
}

function downloadJson() {
  if (!STATE.results.length) {
    toast('Run an inspection first');
    return;
  }
  const payload = {
    exportedAt: new Date().toISOString(),
    timezone: STATE.zone,
    results: STATE.results,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `token-inspector-${Date.now()}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
  toast('JSON report downloaded');
}

/* -------------------------------------------------------------------- wiring */
function wire() {
  $('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = $('loginButton');
    const error = $('loginError');
    if (button.disabled) return;
    error.textContent = '';
    beginBusy(button, 'AUTHENTICATING');
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: val('passwordInput') }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Access denied.');
      await finishBusy(button, 'ACCESS GRANTED', 700);
      await new Promise((resolve) => setTimeout(resolve, 320));
      $('passwordInput').value = '';
      setLocked(false);
      startSessionTimer(data.remaining);
      toast('Console unlocked · 30 min session');
      resetBusy(button);
    } catch (exception) {
      resetBusy(button);
      error.textContent = `✖ ${exception.message || 'Unable to unlock the console.'}`;
      $('authCard').classList.add('shake');
      setTimeout(() => $('authCard').classList.remove('shake'), 450);
    }
  });

  $('revealButton').addEventListener('click', () => {
    const input = $('passwordInput');
    const reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    $('revealButton').textContent = reveal ? 'HIDE' : 'SHOW';
    input.focus();
  });

  $('analyzeButton').addEventListener('click', inspect);
  $('inputData').addEventListener('input', () => {
    const length = val('inputData').length;
    $('charCount').textContent = `${numberText(length)} character${length === 1 ? '' : 's'}`;
  });
  $('inputData').addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      inspect();
    }
  });
  $('clearButton').addEventListener('click', () => {
    $('inputData').value = '';
    $('charCount').textContent = '0 characters';
    $('resultsSection').hidden = true;
    STATE.results = [];
    $('inputData').focus();
  });
  $('pasteButton').addEventListener('click', async () => {
    const button = $('pasteButton');
    beginBusy(button, 'READING');
    try {
      const clip = await navigator.clipboard.readText();
      $('inputData').value = clip;
      $('inputData').dispatchEvent(new Event('input'));
      $('inputData').focus();
      finishBusy(button, 'PASTED', 800);
    } catch {
      resetBusy(button);
      toast('Clipboard access was not granted');
    }
  });
  $('exampleButton').addEventListener('click', () => {
    const button = $('exampleButton');
    beginBusy(button, 'LOADING');
    $('inputData').value = EXAMPLE_URL;
    $('inputData').dispatchEvent(new Event('input'));
    $('inputData').focus();
    finishBusy(button, 'LOADED', 900);
    toast('Example loaded — press Inspect source');
  });

  $('themeButton').addEventListener('click', toggleTheme);
  $('settingsButton').addEventListener('click', () => {
    populateTimezones();
    $('settingsModal').hidden = false;
  });
  $('closeSettings').addEventListener('click', () => {
    $('settingsModal').hidden = true;
  });
  $('settingsModal').addEventListener('click', (event) => {
    if (event.target === $('settingsModal')) $('settingsModal').hidden = true;
  });
  $('timezoneSelect').addEventListener('change', (event) => changeTimezone(event.target.value));
  $('deviceTimeButton').addEventListener('click', () =>
    changeTimezone(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'));
  $('resetTimezone').addEventListener('click', () => {
    changeTimezone('Asia/Kolkata');
    populateTimezones();
  });
  $('clockZone').addEventListener('click', () => {
    populateTimezones();
    $('settingsModal').hidden = false;
  });
  document.querySelectorAll('[data-theme-choice]').forEach((button) => {
    button.addEventListener('click', () => applyTheme(button.dataset.themeChoice));
  });

  $('filterRow').addEventListener('click', (event) => {
    const chip = event.target.closest('.filter-chip');
    if (!chip) return;
    STATE.filter = chip.dataset.filter;
    document.querySelectorAll('.filter-chip').forEach((item) =>
      item.classList.toggle('is-active', item === chip));
    renderList();
  });

  $('copyAllButton').addEventListener('click', async () => {
    const button = $('copyAllButton');
    if (!STATE.results.length) {
      toast('Run an inspection first');
      return;
    }
    if (!beginBusy(button, 'COPYING')) return;
    await copyText(reportText(), 'Report copied');
    finishBusy(button, 'COPIED', 900);
  });
  $('downloadButton').addEventListener('click', () => {
    const button = $('downloadButton');
    if (!STATE.results.length) {
      toast('Run an inspection first');
      return;
    }
    if (!beginBusy(button, 'BUILDING')) return;
    setTimeout(() => {
      downloadJson();
      finishBusy(button, 'SAVED', 900);
    }, 180);
  });

  $('logoutButton').addEventListener('click', async () => {
    const button = $('logoutButton');
    button.classList.add('is-loading');
    await fetch('/api/logout', { method: 'POST' }).catch(() => {});
    button.classList.remove('is-loading');
    clearInterval(STATE.sessionTimer);
    $('sessionPill').classList.remove('is-live');
    $('passwordInput').value = '';
    setLocked(true, 'auth');
    $('loginError').textContent = '';
    toast('Console locked');
  });

  $('installButton').addEventListener('click', async () => {
    if (STATE.installPrompt) {
      STATE.installPrompt.prompt();
      await STATE.installPrompt.userChoice;
      STATE.installPrompt = null;
    } else {
      toast('Use the browser menu and choose Install app');
    }
  });
  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    STATE.installPrompt = event;
  });

  /* guide + access modals */
  const openGuide = () => openModal('guideModal');
  const openAccess = () => openModal('accessModal');
  $('guideButton').addEventListener('click', openGuide);
  $('heroGuide').addEventListener('click', openGuide);
  $('footerGuide').addEventListener('click', openGuide);
  $('lockGuide').addEventListener('click', openGuide);
  $('closeGuide').addEventListener('click', () => closeModal('guideModal'));
  $('accessButton').addEventListener('click', openAccess);
  $('heroAccess').addEventListener('click', openAccess);
  $('footerAccess').addEventListener('click', openAccess);
  $('lockAccess').addEventListener('click', openAccess);
  $('closeAccess').addEventListener('click', () => closeModal('accessModal'));

  ['guideModal', 'accessModal', 'settingsModal'].forEach((id) => {
    $(id).addEventListener('click', (event) => {
      if (event.target === $(id)) closeModal(id);
    });
  });

  $('copyAccessUrl').addEventListener('click', () =>
    copyText('https://token-inspector.onrender.com', 'Console link copied'));
  $('revealAccessKey').addEventListener('click', () => {
    const key = $('accessKey');
    const hidden = key.dataset.hidden === 'true';
    key.dataset.hidden = String(!hidden);
    key.textContent = hidden ? key.dataset.value : '••••';
    $('revealAccessKey').textContent = hidden ? 'hide' : 'reveal';
  });
  $('copyAccessKey').addEventListener('click', () => {
    const key = $('accessKey');
    copyText(key.dataset.value, 'Passkey copied');
    key.dataset.hidden = 'false';
    key.textContent = key.dataset.value;
    $('revealAccessKey').textContent = 'hide';
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    closeModals();
  });

  const media = window.matchMedia('(prefers-color-scheme: light)');
  const onScheme = () => {
    if (STATE.theme === 'system') applyTheme('system');
  };
  if (media.addEventListener) media.addEventListener('change', onScheme);
  else if (media.addListener) media.addListener(onScheme);

  document.querySelectorAll('a.seg[href]').forEach((link) => {
    link.addEventListener('click', () => {
      document.querySelectorAll('a.seg[href]').forEach((item) => item.classList.remove('is-active'));
      link.classList.add('is-active');
    });
  });
}

/* ---------------------------------------------------------------------- init */
function init() {
  STATE.zone = safeZone(localStorage.getItem(KEY_ZONE) || 'Asia/Kolkata');
  applyTheme(localStorage.getItem(KEY_THEME) || 'dark');
  $('footerZone').textContent = STATE.zone;
  populateTimezones();
  wire();
  tickClock();
  clearInterval(STATE.clockTimer);
  STATE.clockTimer = setInterval(tickClock, 1000);
  refreshSession();
  clearInterval(STATE.sessionSync);
  STATE.sessionSync = setInterval(() => {
    if (!$('accessOverlay').classList.contains('is-hidden')) return;
    syncSession();
  }, 45000);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && $('accessOverlay').classList.contains('is-hidden')) syncSession();
  });
  $('charCount').textContent = '0 characters';
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
