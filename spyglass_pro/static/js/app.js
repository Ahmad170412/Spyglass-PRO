/* ── API token ── */
/* When SPYGLASS_PRO_TOKEN is set server-side, every /api/*
   call must carry it. A token passed in the URL (?token=...)
   is remembered in localStorage and sent as a Bearer header;
   a 401 prompts for it once. */
var API_TOKEN = null;
(function () {
  var m = /[?&]token=([^&]+)/.exec(window.location.search);
  if (m) {
    try {
      localStorage.setItem('spyglass_token', decodeURIComponent(m[1]));
      window.history.replaceState(null, '', window.location.pathname);
    } catch (e) { /* private mode etc. — token just won't persist */ }
  }
  try { API_TOKEN = localStorage.getItem('spyglass_token'); } catch (e) {}
})();

function apiFetch(url, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  if (API_TOKEN) opts.headers['Authorization'] = 'Bearer ' + API_TOKEN;
  return fetch(url, opts).then(function (r) {
    if (r.status !== 401) return r;
    try { localStorage.removeItem('spyglass_token'); } catch (e) {}
    var t = window.prompt('Spyglass-Pro API token:');
    if (!t) throw new Error('unauthorized');
    API_TOKEN = t;
    try { localStorage.setItem('spyglass_token', t); } catch (e) {}
    opts.headers['Authorization'] = 'Bearer ' + t;
    return fetch(url, opts);
  });
}

/* Only http(s)/mailto links may be rendered as <a href> — scan
   results contain third-party URLs, and a javascript: URL there
   would be stored XSS. Anything else renders as inert text. */
function safeHref(url) {
  try {
    var u = new URL(url);
    if (['http:', 'https:', 'mailto:'].indexOf(u.protocol) === -1) return '';
    return u.href;
  } catch (e) {
    return '';
  }
}

document.addEventListener('DOMContentLoaded', function () {

  /* ── Navigation ── */
  var navItems = document.querySelectorAll('.nav-item');
  var panels = document.querySelectorAll('.panel');

  function activatePanel(panelId) {
    navItems.forEach(function (n) { n.classList.remove('active'); });
    panels.forEach(function (p) { p.classList.remove('active'); });
    var navItem = document.querySelector('.nav-item[data-panel="' + panelId + '"]');
    if (navItem) navItem.classList.add('active');
    var target = document.getElementById('panel-' + panelId);
    if (target) target.classList.add('active');
    var main = document.getElementById('mainContent');
    if (main) main.scrollTop = 0;
    /* Re-read on open: runs stored by another tab or a CLI scan since the
       last load belong in the table too. */
    if (panelId === 'cases') loadCases();
    /* Fresh on open: another tab may have added or checked a target. */
    if (panelId === 'targets') loadTargets();
    if (panelId === 'settings') loadBurnerSettings();
  }

  navItems.forEach(function (item) {
    item.addEventListener('click', function () {
      activatePanel(item.getAttribute('data-panel'));
      /* Platform shortcut tabs share one panel: highlight the clicked tab
         (not the first one for that panel) and preselect its platform. */
      var plat = item.getAttribute('data-platform');
      if (plat) {
        navItems.forEach(function (n) { n.classList.remove('active'); });
        item.classList.add('active');
        selectSocialPlatform(plat);
      }
    });
  });

  /* ── Proxy status (topbar indicator; editing lives in Settings) ── */
  var proxyStatus = document.getElementById('proxyStatus');

  function updateProxyUI(proxy) {
    if (!proxyStatus) return;
    var dot = proxyStatus.querySelector('.dot');
    var label = proxyStatus.querySelector('.proxy-label');
    if (proxy) {
      dot.className = 'dot active';
      label.textContent = proxy;
    } else {
      dot.className = 'dot idle';
      label.textContent = 'No Proxy';
    }
  }

  /* ── Generic run dispatcher ── */
  /* Only forms that declare a data-api are scans; the cases form reuses
     .module-form for styling but drives store queries of its own. */
  document.querySelectorAll('.module-form[data-api]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var api = form.getAttribute('data-api');
      var resultsId = form.getAttribute('data-results');
      var targetEl = document.getElementById(form.getAttribute('data-target') || '');
      var target = targetEl ? targetEl.value.trim() : '';
      var qtype = form.getAttribute('data-qtype') || '';

      if (targetEl && !target) {
        showToast('Enter a target', 'error');
        return;
      }

      var btn = form.querySelector('.run-btn');
      setLoading(btn, true);
      var preflightQ = qtype || (api === 'investigate' ? 'investigate' : api);
      showScanning(resultsId, target, false, preflightQ);

      var flags = {};
      form.querySelectorAll('[data-flag]').forEach(function (el) {
        if (el.type === 'checkbox') {
          if (el.checked) flags[el.getAttribute('data-flag')] = '1';
        } else if (el.value) {
          flags[el.getAttribute('data-flag')] = el.value;
        }
      });
      form.querySelectorAll('[data-flag-input]').forEach(function (el) {
        if (el.value) flags[el.getAttribute('data-flag-input')] = el.value;
      });

      if (api === 'investigate') {
        var payload = {};
        form.querySelectorAll('[data-key]').forEach(function (el) {
          payload[el.getAttribute('data-key')] = el.value.trim();
        });
        /* The option checkboxes (json/csv/report/store) are flags, not
           target fields — they have to ride along or they do nothing. */
        Object.keys(flags).forEach(function (k) { payload[k] = flags[k]; });
        runAsyncScan({
          url: '/api/investigate/run', method: 'POST', body: payload,
          resultsId: resultsId, target: target, qtype: 'investigate', btn: btn
        });
        return;
      }

      var params = new URLSearchParams();
      if (api === 'spyglass') {
        params.set('module', qtype);
        params.set('target', target);
        Object.keys(flags).forEach(function (k) { params.set(k, flags[k]); });
        runAsyncScan({
          url: '/api/spyglass/run?' + params.toString(), method: 'GET',
          resultsId: resultsId, target: target, qtype: qtype, btn: btn
        });
        return;
      }

      /* Social checks no longer ride this dispatcher: form-social has no
         data-api because a check only exists against a tracked target —
         the TARGETS/CHECK AGAIN flow (checkTarget below) owns it. */
      setLoading(btn, false);
      clearScan(resultsId);
      showToast('Unknown API: ' + api, 'error');
    });
  });

  /* ── Load status on startup ── */
  apiFetch('/api/status').then(function (r) { return r.json(); }).then(function (data) {
    updateProxyUI(data.proxy || '');
    updateEngineTags(data);
    updateOverview(data);
  }).catch(function () {
    showToast('Server unreachable', 'error');
  });

  /* ── Cases: diff / timeline / dossier ── */
  /* The cases form deliberately has no data-api: it is excluded from the
     generic run dispatcher above and drives the store queries instead. */
  var casesForm = document.getElementById('form-cases');
  if (casesForm) {
    casesForm.addEventListener('submit', function (e) { e.preventDefault(); });
  }

  /* Clicking a stored case loads that exact target and query type, so the
     filters can never be left pointing at someone else's target. */
  var casesList = document.getElementById('casesList');
  if (casesList) {
    casesList.addEventListener('click', function (e) {
      /* Delete button first: it lives inside the row, so it must win
         over the row-click timeline loader below. */
      var del = e.target.closest && e.target.closest('[data-del-id]');
      if (del) {
        e.stopPropagation();
        deleteCase(del.getAttribute('data-del-id'), del.getAttribute('data-del-qtype') || '', del);
        return;
      }
      var row = e.target.closest && e.target.closest('tr.case-row');
      if (!row) return;
      /* A legacy Lens run has no timeline in this build — say so instead
         of loading a target that answers "no stored runs". */
      if (row.getAttribute('data-legacy') === '1') {
        showToast('Legacy Lens-Extender case — history is not available in this build.', 'error');
        return;
      }
      var target = row.getAttribute('data-target') || '';
      var qtype = row.getAttribute('data-qtype') || '';
      document.getElementById('casesTarget').value = target;
      var sel = document.getElementById('casesQtype');
      if (sel) sel.value = qtype;
      casesQuery('timeline');
    });
  }

  /* "Search all query types" inside an empty-state message. */
  var casesDetail = document.getElementById('casesDetail');
  if (casesDetail) {
    casesDetail.addEventListener('click', function (e) {
      if (e.target.id === 'casesResetQtype') {
        e.preventDefault();
        var sel = document.getElementById('casesQtype');
        if (sel) sel.value = '';
        casesQuery('timeline');
        return;
      }
      if (e.target.id === 'dossierCopy') { copyDossier(); return; }
      if (e.target.id === 'dossierDl') { downloadDossier(); return; }
    });
  }
  var caseButtons = [
    ['casesDiffBtn', 'diff'],
    ['casesTimelineBtn', 'timeline'],
    ['casesProfileBtn', 'profile']
  ];
  caseButtons.forEach(function (pair) {
    var btn = document.getElementById(pair[0]);
    if (btn) btn.addEventListener('click', function () { casesQuery(pair[1]); });
  });

  /* ── Load cases + platform registry + settings vault ── */
  loadCases();
  loadSocialPlatforms();
  loadSettings();
  var settingsSave = document.getElementById('settingsSave');
  if (settingsSave) settingsSave.addEventListener('click', saveSettings);
  var settingsReload = document.getElementById('settingsReload');
  if (settingsReload) settingsReload.addEventListener('click', loadSettings);
  var settingsGrid = document.getElementById('settingsGrid');
  if (settingsGrid) {
    settingsGrid.addEventListener('click', settingsGridClick);
    settingsGrid.addEventListener('keydown', settingsGridKeydown);
  }
});

/* ── API Helpers ── */
function showToast(msg, type) {
  var container = document.getElementById('toastContainer');
  var toast = document.createElement('div');
  toast.className = 'toast ' + (type || 'info');
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(function () { toast.remove(); }, 4000);
}

/* Themed replacement for window.confirm. Resolves true only when the
   operator submits the confirm button; Esc, backdrop clicks and Cancel
   all resolve false. */
function confirmAction(options) {
  var dialog = document.getElementById('confirmDialog');
  if (!dialog || typeof dialog.showModal !== 'function') return Promise.resolve(false);
  if (dialog.open) dialog.close('cancel');
  var opts = options || {};
  document.getElementById('confirmKicker').textContent = opts.kicker || 'Confirm action';
  document.getElementById('confirmTitle').textContent = opts.title || 'Are you sure?';
  document.getElementById('confirmBody').textContent = opts.body || '';
  document.getElementById('confirmCancel').textContent = opts.cancelLabel || 'Cancel';
  var ok = document.getElementById('confirmOk');
  ok.textContent = opts.confirmLabel || 'Confirm';
  ok.className = 'btn btn-sm ' + (opts.danger === false ? 'btn-primary' : 'btn-danger');
  dialog.returnValue = '';
  if (!dialog.dataset.backdropBound) {
    dialog.dataset.backdropBound = '1';
    dialog.addEventListener('click', function (event) {
      if (event.target === dialog) dialog.close('cancel');
    });
  }
  return new Promise(function (resolve) {
    function done() {
      dialog.removeEventListener('close', done);
      resolve(dialog.returnValue === 'confirm');
    }
    dialog.addEventListener('close', done);
    try {
      dialog.showModal();
    } catch (err) {
      dialog.removeEventListener('close', done);
      resolve(false);
      return;
    }
    var cancel = document.getElementById('confirmCancel');
    if (cancel) cancel.focus();
  });
}

/* Optional recon tools (sherlock, maigret, holehe, ignorant, ...) are
   discovered on PATH. A missing one does not fail a scan — the engine
   skips that leg — so without this the UI would present a partial result
   as a complete one. */
var STATUS = null;

function updateEngineTags(data) {
  STATUS = data || null;
  // The topbar engine pills are gone (replaced by the Overview data-source
  // grid), but the partial-recon banner still needs its status snapshot —
  // an early return here once silently killed it. Never gate this on DOM.
  renderMissingNotice();
}

/* A quiet line on the panels whose recon legs are incomplete. */
function renderMissingNotice() {
  var notice = document.getElementById('toolNotice');
  if (!notice || !STATUS) return;
  var degraded = STATUS.degraded || {};
  var lines = [];
  var labels = { email: 'Email', username: 'Username', phone: 'Phone',
                 website: 'Website', metadata: 'Metadata' };
  Object.keys(degraded).forEach(function (qtype) {
    lines.push((labels[qtype] || qtype) + ': no ' + degraded[qtype].join(', '));
  });
  if (!lines.length) {
    notice.innerHTML = '';
    notice.style.display = 'none';
    return;
  }
  notice.style.display = 'block';
  notice.innerHTML = '<span class="tool-notice-title">Partial recon</span> Some optional ' +
    'tools are not installed, so those legs are skipped: ' + escapeHtml(lines.join(' · ')) +
    '. <code>pip install holehe sherlock maigret ignorant</code> or <code>brew install</code> them to enable.';
}

function setLoading(btn, loading) {
  if (!btn) return;
  if (!btn.getAttribute('data-original-text')) {
    btn.setAttribute('data-original-text', btn.textContent);
  }
  if (loading) {
    btn.disabled = true;
    btn.classList.add('loading');
    btn.innerHTML = '<span class="spinner"></span> Running<span class="ellipsis"></span>';
  } else {
    btn.disabled = false;
    btn.classList.remove('loading');
    btn.textContent = btn.getAttribute('data-original-text');
  }
}

/* ── In-progress scanning card: live engine log, not theater ──
 *
 * The radar/bar only mean "the server is working" (indeterminate). The
 * live log lines below them are REAL — pushed by the engine as each leg
 * runs, via /api/stream/<job_id> (SSE), with /api/job/<id> polling as
 * fallback when streams are full. The rotating fake verbs are gone. */
var activeScans = {};

function fmtElapsed(ms) {
  var s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
}

function clearScan(resultsId) {
  var scan = activeScans[resultsId];
  if (scan) {
    scan.cancelled = true;
    clearInterval(scan.timer);
    if (scan.pollTimer) clearTimeout(scan.pollTimer);
    if (scan.abort) { try { scan.abort.abort(); } catch (e) {} }
    delete activeScans[resultsId];
  }
  var card = document.getElementById('scanning-' + resultsId);
  if (card) card.remove();
}

function showScanning(resultsId, target, append, qtype) {
  clearScan(resultsId);
  var container = document.getElementById(resultsId);
  if (!container) return;
  var start = Date.now();
  var safeTarget = target ? String(target).slice(0, 120) : '';
  var html = '<div class="result-card scan-card" id="scanning-' + resultsId + '">' +
    '<div class="scan-radar"><span></span><span></span><span></span><i></i></div>' +
    '<div class="scan-title">Scan in progress</div>' +
    (safeTarget ? '<div class="scan-target">' + escapeHtml(safeTarget) + '</div>' : '') +
    '<div class="preflight" id="preflight-' + resultsId + '">' + preflightHtml(qtype || '') + '</div>' +
    '<div class="scan-status"><span class="live-dot"></span><span class="scan-live">Connecting to live log…</span></div>' +
    '<div class="scan-bar"><span></span></div>' +
    '<div class="scan-log" id="scanlog-' + resultsId + '"><div class="scan-log-lines"></div></div>' +
    '<div class="scan-timer">0s elapsed</div>' +
    '</div>';
  if (append) container.insertAdjacentHTML('afterbegin', html);
  else container.innerHTML = html;
  var card = document.getElementById('scanning-' + resultsId);
  var timerEl = card ? card.querySelector('.scan-timer') : null;
  activeScans[resultsId] = {
    timer: setInterval(function () {
      if (timerEl) timerEl.textContent = fmtElapsed(Date.now() - start) + ' elapsed';
    }, 1000),
    cancelled: false,
    lines: 0
  };
  // Fresh tool status in the background: the pre-flight line above renders
  // from cache instantly, then corrects itself if anything changed.
  refreshPreflight(resultsId, qtype || '');
}

function appendScanLog(resultsId, line) {
  var scan = activeScans[resultsId];
  var box = document.getElementById('scanlog-' + resultsId);
  if (!box) return;
  var lines = box.querySelector('.scan-log-lines');
  if (!lines) return;
  var div = document.createElement('div');
  div.className = 'run-log-line';
  div.textContent = line;
  lines.appendChild(div);
  while (lines.children.length > 40) lines.removeChild(lines.firstChild);
  box.scrollTop = box.scrollHeight;
  if (scan) {
    scan.lines += 1;
    var card = document.getElementById('scanning-' + resultsId);
    var live = card ? card.querySelector('.scan-live') : null;
    if (live) live.textContent = 'Live · ' + scan.lines + ' line' + (scan.lines === 1 ? '' : 's');
  }
}

/* ── Pre-flight power check ──
 *
 * Rendered from the cached /api/status (+ vault snapshot) before every
 * scan: which legs will actually run and which are skipped. A partial
 * result must never look like a complete one, so the scan says so up
 * front instead of after. */
var PREFLIGHT_TOOLS = {
  email: ['holehe', 'user-scanner', 'blackbird'],
  username: ['user-scanner', 'sherlock', 'maigret', 'blackbird'],
  phone: ['ignorant', 'phoneinfoga'],
  website: ['dig', 'whois'],
  metadata: ['exiftool'],
  opsec: [],
  social: []
};
var PREFLIGHT_KEYS = {
  darkweb: [['intelx_api_key', 'IntelX'], ['hibp_api_key', 'HIBP']],
  email: [['hibp_api_key', 'HIBP']],
  username: [['hibp_api_key', 'HIBP']],
  phone: [['hibp_api_key', 'HIBP']]
};
/* What each missing key would actually unlock, in the operator's words
 * from the vault — so PARTIAL POWER names the upgrade, not just the gap.
 * Phrases mirror the Settings help text; adding a key here without the
 * engine honoring it would be a lie, so keep the two in step. */
var PREFLIGHT_WHY = {
  intelx_api_key: 'paste + breach archive',
  hibp_api_key: 'authoritative breach list'
};
var SETTINGS_CACHE = null;

function settingsKeySet(key) {
  if (!SETTINGS_CACHE || !SETTINGS_CACHE.keys) return null;
  for (var i = 0; i < SETTINGS_CACHE.keys.length; i++) {
    if (SETTINGS_CACHE.keys[i].key === key) return !!SETTINGS_CACHE.keys[i].configured;
  }
  return null;
}

function preflightHtml(qtype) {
  var tools = (STATUS && STATUS.tools) || {};
  var degraded = (STATUS && STATUS.degraded) || {};
  var needed = PREFLIGHT_TOOLS[qtype];
  var keySpecs = PREFLIGHT_KEYS[qtype];
  // Investigation spans every leg: summarise across all tool groups.
  if (qtype === 'investigate') {
    var all = [];
    Object.keys(PREFLIGHT_TOOLS).forEach(function (k) {
      (PREFLIGHT_TOOLS[k] || []).forEach(function (t) { if (all.indexOf(t) === -1) all.push(t); });
    });
    needed = all;
  }
  var bits = [];
  var full = true;
  if (needed && needed.length) {
    var have = needed.filter(function (t) { return tools[t]; });
    var missing = needed.filter(function (t) { return !tools[t]; });
    if (missing.length) full = false;
    bits.push(have.length + '/' + needed.length + ' tools detected' +
      (missing.length ? ' — missing ' + missing.join(', ') : ' — ' + needed.join(', ')));
  } else if (qtype === 'social') {
    /* No CLI legs and no keys: the panel is the registry. A healthy
       social scan adds NO detail line — the platform roll-call is
       documentation, not scan status, and it added a line of noise to
       every run. The badge alone is the answer; only a dead engine
       speaks. */
    var nplats = ((STATUS && STATUS.platforms) || []).length;
    if (!nplats) {
      full = false;
      bits.push('social engine failed to load');
    }
  } else if (degraded[qtype]) {
    full = false;
    bits.push('missing ' + degraded[qtype].join(', '));
  }
  if (keySpecs) {
    var haveK = keySpecs.filter(function (spec) { return settingsKeySet(spec[0]); });
    var unknown = keySpecs.some(function (spec) { return settingsKeySet(spec[0]) === null; });
    if (haveK.length < keySpecs.length) full = false;
    bits.push('enrichment ' + haveK.length + '/' + keySpecs.length + ' keys' +
      (haveK.length ? ' (' + haveK.map(function (s) { return s[1]; }).join(', ') + ')' : '') +
      (unknown ? ' — open Settings to check' : ''));
    /* Name the upgrade, not just the gap: each missing key with what it
       unlocks on this run. Only when the vault state is known — a null
       cache must not present guesses as missing keys. */
    if (!unknown) {
      var missingK = keySpecs.filter(function (spec) { return !settingsKeySet(spec[0]); });
      if (missingK.length) {
        bits.push('add ' + missingK.map(function (spec) {
          var why = PREFLIGHT_WHY[spec[0]];
          return spec[1] + (why ? ' (' + why + ')' : '');
        }).join(' + ') + ' in Settings');
      }
    }
  }
  if (!bits.length) {
    if (!STATUS) return '<span class="power-badge partial">CHECKING TOOLS…</span>';
    if (qtype === 'social') return '<span class="power-badge full">FULL POWER</span>';
    return '<span class="power-badge full">FULL POWER</span><span class="preflight-detail">keyless legs + breach data</span>';
  }
  return '<span class="power-badge ' + (full ? 'full' : 'partial') + '">' +
    (full ? 'FULL POWER' : 'PARTIAL POWER') + '</span>' +
    '<span class="preflight-detail">' + escapeHtml(bits.join(' · ')) + '</span>';
}

function refreshPreflight(resultsId, qtype) {
  apiFetch('/api/status').then(function (r) { return r.json(); }).then(function (data) {
    updateProxyUI(data.proxy || '');
    updateEngineTags(data);
    var el = document.getElementById('preflight-' + resultsId);
    if (el) el.innerHTML = preflightHtml(qtype);
  }).catch(function () {});
}

/* ── Async scan engine: submit non-blocking, stream the live log ── */
function sseHeaders() {
  var headers = {};
  if (API_TOKEN) headers['Authorization'] = 'Bearer ' + API_TOKEN;
  return headers;
}

function runAsyncScan(opts) {
  var url = opts.url, method = opts.method || 'GET';
  var resultsId = opts.resultsId, qtype = opts.qtype || '';
  var btn = opts.btn || null, append = !!opts.append;
  var fetchOpts = { headers: sseHeaders() };
  if (method === 'POST') {
    var body = opts.body || {};
    body.async = '1';
    fetchOpts.method = 'POST';
    fetchOpts.headers['Content-Type'] = 'application/json';
    fetchOpts.body = JSON.stringify(body);
  } else {
    url += (url.indexOf('?') === -1 ? '?' : '&') + 'async=1';
  }
  apiFetch(url, fetchOpts).then(function (r) { return r.json(); }).then(function (data) {
    if (data && data.job_id) {
      streamJob(data.job_id, opts);
    } else {
      // Synchronous answer (queue rejection, validation error, …).
      setLoading(btn, false);
      displayResults(resultsId, data, append, qtype, opts.target);
      if (opts.onDone) opts.onDone(data);
    }
  }).catch(function (err) {
    var scan = activeScans[resultsId];
    if (scan && scan.cancelled) return;
    setLoading(btn, false);
    clearScan(resultsId);
    /* A request-level failure never reaches onDone — tell the caller so
       a scan-mode UI can restore itself instead of hiding forever. */
    if (opts.onFail) opts.onFail(err);
    showToast('Error: ' + err.message, 'error');
  });
}

function finishAsyncScan(opts, result) {
  var scan = activeScans[opts.resultsId];
  if (scan && scan.cancelled) return;
  setLoading(opts.btn || null, false);
  displayResults(opts.resultsId, result, !!opts.append, opts.qtype || '', opts.target);
  if (opts.onDone) opts.onDone(result);
}

function streamJob(jobId, opts) {
  var resultsId = opts.resultsId;
  var scan = activeScans[resultsId];
  if (!scan) return;
  var controller = null;
  try { controller = new AbortController(); scan.abort = controller; } catch (e) {}
  var streamUrl = '/api/stream/' + encodeURIComponent(jobId);
  var headers = sseHeaders();
  fetch(streamUrl, { headers: headers, signal: controller ? controller.signal : undefined })
    .then(function (resp) {
      if (!resp.ok || !resp.body) { pollJob(jobId, opts, 0); return null; }
      var reader = resp.body.getReader();
      var decoder = new TextDecoder();
      var buf = '';
      var finished = false;
      function pump() {
        return reader.read().then(function (chunk) {
          var cur = activeScans[resultsId];
          if (!cur || cur.cancelled) { try { reader.cancel(); } catch (e) {} return; }
          if (chunk.done) {
            if (!finished) pollJob(jobId, opts, cur.lines);
            return;
          }
          buf += decoder.decode(chunk.value, { stream: true });
          var frames = buf.split('\n\n');
          buf = frames.pop();
          frames.forEach(function (frame) {
            var event = null, payload = null;
            frame.split('\n').forEach(function (ln) {
              if (ln.indexOf('event:') === 0) event = ln.slice(6).trim();
              else if (ln.indexOf('data:') === 0) payload = ln.slice(5).trim();
            });
            if (!event || payload === null) return; // : ping keep-alive
            if (event === 'log') {
              try { appendScanLog(resultsId, JSON.parse(payload).line); } catch (e) {}
            } else if (event === 'done') {
              finished = true;
              try { reader.cancel(); } catch (e) {}
              var result = {};
              try { result = JSON.parse(payload); } catch (e) {}
              finishAsyncScan(opts, result);
            } else if (event === 'error') {
              finished = true;
              try { reader.cancel(); } catch (e) {}
              pollJob(jobId, opts, (activeScans[resultsId] || {}).lines || 0);
            }
          });
          return pump();
        });
      }
      return pump();
    }).catch(function () {
      var cur = activeScans[resultsId];
      if (cur && !cur.cancelled) pollJob(jobId, opts, cur.lines || 0);
    });
}

function pollJob(jobId, opts, seen) {
  var resultsId = opts.resultsId;
  var scan = activeScans[resultsId];
  if (!scan || scan.cancelled) return;
  apiFetch('/api/job/' + encodeURIComponent(jobId)).then(function (r) { return r.json(); }).then(function (job) {
    var cur = activeScans[resultsId];
    if (!cur || cur.cancelled) return;
    cur.pollFails = 0;
    if (job.error && job.error.indexOf('unknown job') === 0) {
      finishAsyncScan(opts, { error: job.error });
      return;
    }
    var lines = job.progress || [];
    for (var i = seen; i < lines.length; i++) appendScanLog(resultsId, lines[i]);
    if (job.status === 'done') {
      finishAsyncScan(opts, job.result || { error: job.error || 'empty result' });
      return;
    }
    cur.pollTimer = setTimeout(function () { pollJob(jobId, opts, lines.length); }, 1500);
  }).catch(function (err) {
    var cur = activeScans[resultsId];
    if (!cur || cur.cancelled) return;
    /* A server restart mid-scan used to retry forever: the card sat on
       "scan in progress" with a ticking timer and lines that would never
       come. Bounded now — a minute of refused connections means the
       server is gone, so say so instead of pretending to still scan. */
    cur.pollFails = (cur.pollFails || 0) + 1;
    if (cur.pollFails > 20) {
      finishAsyncScan(opts, { error: 'connection to the server was lost — ' +
        'this check may have finished on the server side; reload the page to see it' });
      return;
    }
    cur.pollTimer = setTimeout(function () { pollJob(jobId, opts, seen); }, 3000);
  });
}

/* ── Result card chrome ──
 *
 * A finished card answers two questions and nothing else: what was found,
 * and which tool found it. Everything else a run carries — the progress
 * log, derived findings, module diagnostics, artifacts, the raw payload —
 * sleeps behind a disclosure until asked for. A result that needs its log
 * read to be understood is not a result. */
var RESULT_KIND = {
  email: 'Email', username: 'Username', phone: 'Phone', website: 'Website',
  darkweb: 'Dark web', investigate: 'Investigation', investigation: 'Investigation',
  opsec: 'OPSEC', metadata: 'Metadata', social: 'Social'
};

function resultKind(data, qtype) {
  if (data && data.platform) return String(data.platform);
  return RESULT_KIND[qtype] || (qtype ? String(qtype) : 'Result');
}

function socialHandle(value) {
  var v = String(value || '');
  return v.charAt(0) === '@' ? v : '@' + v;
}

function resultTarget(data, qtype, fallback) {
  if (fallback) return qtype === 'social' ? socialHandle(fallback) : fallback;
  if (data && data.target) return String(data.target);
  if (data && data.handle) return socialHandle(data.handle);
  if (data && data.query) return String(data.query);
  if (data && data.inputs && typeof data.inputs === 'object') {
    return Object.keys(data.inputs).map(function (k) { return data.inputs[k]; })
      .filter(function (v) { return v; }).join(' · ');
  }
  return '';
}

function resultHead(data, qtype, target) {
  var html = '<div class="result-head"><span class="result-kind">' +
             escapeHtml(resultKind(data, qtype)) + '</span>';
  var t = resultTarget(data, qtype, target);
  if (t) html += '<span class="result-target">' + escapeHtml(t) + '</span>';
  return html + '</div>';
}

/* One collapsed drawer. The summary is the only visible part — it reads as
   a small tab, and opening it claims the full card width. */
function resultTab(label, inner, count) {
  if (!inner) return '';
  var n = (count === undefined || count === null) ? '' : ' (' + count + ')';
  return '<details class="result-tab"><summary>' + escapeHtml(label) + n +
         '</summary><div class="result-tab-body">' + inner + '</div></details>';
}

function runLogHtml(lines) {
  var html = '<div class="run-log">';
  lines.forEach(function (line) {
    html += '<div class="run-log-line">' + escapeHtml(line) + '</div>';
  });
  return html + '</div>';
}

function artifactsHtml(items) {
  var html = '<div class="artifact-list">';
  items.forEach(function (a) {
    html += '<div class="artifact-item"><span class="artifact-kind">' +
            escapeHtml(a.kind) + '</span><code>' + escapeHtml(a.path) +
            '</code></div>';
  });
  return html + '</div>';
}

function displayResults(containerId, data, append, qtype, target) {
  clearScan(containerId);
  var container = document.getElementById(containerId);
  if (!container) return;

  var html;
  if (!data || (typeof data === 'object' && Object.keys(data).length === 0)) {
    html = '<div class="result-card"><p class="dim">No results returned.</p></div>';
  } else if (data.error) {
    html = '<div class="result-card">' + resultHead(data, qtype, target) +
           '<p class="status-err">Error: ' + escapeHtml(data.error) + '</p></div>';
  } else {
    var result = renderResult(data, qtype || '');
    html = '<div class="result-card">';
    html += resultHead(data, qtype, target);
    if (data.summary) {
      html += '<p class="result-summary">' + escapeHtml(data.summary) + '</p>';
    }
    html += '<div class="result-body">' + result.body + '</div>';

    /* Everything the card deliberately does not show on its face. */
    var details = '';
    if (data.normalized) details += renderNormalized(data.normalized);
    if (result.details) details += result.details;
    if (Array.isArray(data.artifacts) && data.artifacts.length) {
      details += '<span class="result-subtitle">Artifacts</span>' +
                 artifactsHtml(data.artifacts);
    }
    if (data.stored_run_id) {
      details += '<div class="artifact-list"><span class="result-subtitle">Stored</span>' +
                 '<div class="artifact-item"><span class="artifact-kind">case</span>' +
                 '<code>run #' + escapeHtml(String(data.stored_run_id)) +
                 ' — visible under Stored Cases</code></div></div>';
    }
    if (data.artifact_error) {
      details += '<p class="status-err">Export error: ' + escapeHtml(data.artifact_error) + '</p>';
    }
    if (data.facts_error) {
      details += '<p class="status-err">Findings error: ' + escapeHtml(data.facts_error) + '</p>';
    }

    var tabs = '';
    if (details) tabs += resultTab('Details', details);
    if (Array.isArray(data.progress) && data.progress.length) {
      tabs += resultTab('Run log', runLogHtml(data.progress), data.progress.length);
    }
    var raw = typeof data === 'object' ? JSON.stringify(data, null, 2) : String(data);
    tabs += resultTab('Raw JSON', '<pre>' + escapeHtml(raw) + '</pre>');
    html += '<div class="result-tabs">' + tabs + '</div>';
    html += '<div class="export-btns">';
    html += '<button class="btn btn-sm btn-outline" onclick="copyResult(\'' + containerId + '\')">Copy JSON</button>';
    html += '</div></div>';
  }

  if (append) {
    container.insertAdjacentHTML('beforeend', html);
  } else {
    container.innerHTML = html;
  }

  /* A stored run changes the Cases table — refresh it in place so the
     newest scan shows up without a page reload. */
  if (data && data.stored_run_id) {
    loadCases();
  }
}

/* ── Structured result rendering ── */
/* ── Render registry ──
   Each result type declares how to recognise and render itself, so adding
   a result type is one entry here instead of another branch in a chain
   that every new type has to be threaded through. `matches` is checked in
   order; the first hit wins. Order matters only where two shapes could
   both match, so keep the specific ones above the generic ones. */
var RENDERERS = [
  { name: 'social',     matches: function (d) { return d.platform !== undefined && d.handle !== undefined; },
    render: renderSocial, details: renderSocialDetails },
  { name: 'investigate', matches: function (d, q) {
      return q === 'investigate' || q === 'investigation' ||
             d.entities !== undefined || d.person !== undefined;
    },
    render: renderInvestigate, details: renderInvestigateDetails },
  { name: 'opsec',      matches: function (d) { return d.direct !== undefined && d.recommendations !== undefined; },
    render: renderOpsec },
  { name: 'phone',      matches: function (d) { return d.phonenumbers !== undefined; },
    render: renderPhone },
  { name: 'website',    matches: function (d) {
      return d.whois !== undefined || d.dns_records !== undefined || d.ct !== undefined; },
    render: renderWebsite },
  { name: 'darkweb',    matches: function (d) { return d.ahmia !== undefined; },
    render: renderDarkweb },
  { name: 'username',   matches: function (d) {
      return d.all_4 !== undefined || d.all_3_no_bb !== undefined ||
             d.all_3_no_mg !== undefined || d.all_3_no_sh !== undefined ||
             d.all_3_no_us !== undefined || d.us_only !== undefined ||
             d.sherlock_only !== undefined || d.maigret_only !== undefined;
    },
    render: renderUsername },
  { name: 'email',      matches: function (d) {
      return d.both !== undefined || d.holehe_only !== undefined ||
             d.user_scanner_only !== undefined;
    },
    render: renderEmail }
];

/* Renderers may expose a `details` builder for content that belongs in the
   collapsed Details drawer rather than the result body. `renderResult`
   returns both halves; `renderBody` stays string-only for nested calls
   (investigation sub-results, legacy callers). */
function renderResult(data, qtype) {
  for (var i = 0; i < RENDERERS.length; i++) {
    var entry = RENDERERS[i];
    if (entry.matches(data, qtype)) {
      return {
        body: entry.render(data, qtype) || '',
        details: entry.details ? (entry.details(data, qtype) || '') : ''
      };
    }
  }
  return { body: renderGeneric(data), details: '' };
}

function renderBody(data, qtype) {
  return renderResult(data, qtype).body;
}

/* ── Social (registry-driven, one layout for every platform) ── *//* Mirror of PROFILE_FIELDS in spyglass_pro/social/schema.py — the field
   metadata lives in Python and this is its renderer-side copy. Keep the
   two in step: tests/test_social.py parses this block and fails if it
   drifts from the Python tuple (key order, label and type). */
var SOCIAL_FIELDS = [
  { key: 'display_name', label: 'Name', type: 'text' },
  { key: 'bio', label: 'Bio', type: 'text' },
  { key: 'url', label: 'Profile URL', type: 'link' },
  { key: 'follower_count', label: 'Followers', type: 'count' },
  { key: 'following_count', label: 'Following', type: 'count' },
  { key: 'post_count', label: 'Posts', type: 'count' },
  { key: 'verified', label: 'Verified', type: 'bool' },
  { key: 'private', label: 'Private', type: 'bool' },
  { key: 'joined', label: 'Joined', type: 'date' },
  { key: 'location', label: 'Location', type: 'text' },
  { key: 'website', label: 'Website', type: 'link' },
  { key: 'avatar_url', label: 'Avatar', type: 'image' },
  { key: 'contact_email', label: 'Contact Email', type: 'text' },
  { key: 'external_links', label: 'External Links', type: 'list' }
];

function pluralize(n, one) {
  return n + ' ' + (n === 1 ? one : one + 's');
}

function socialCell(field, value) {
  if (field.type === 'count' && typeof value === 'number') {
    return value.toLocaleString();
  }
  if (field.type === 'date' && value) {
    return escapeHtml(String(value).slice(0, 10));
  }
  if (field.type === 'bool') {
    return value ? 'yes' : 'no';
  }
  if (field.type === 'list') {
    return value.map(function (item) {
      var href = safeHref(item);
      return href ? '<a href="' + escapeHtml(href) + '" target="_blank" rel="noopener">' +
                    escapeHtml(item) + '</a>' : escapeHtml(item);
    }).join(', ');
  }
  if (field.type === 'link' || field.type === 'image') {
    var link = safeHref(value);
    return link ? '<a href="' + escapeHtml(link) + '" target="_blank" rel="noopener">' +
                  escapeHtml(value) + '</a>' : escapeHtml(value);
  }
  return escapeHtml(value);
}

function renderSocial(d) {
  var html = '';

  if (d.error) {
    html += '<p class="res-line">Error: <span class="status-err">' +
            escapeHtml(d.error) + '</span></p>';
  }

  /* Fields the platform can never return are omitted, not shown as empty,
     so a blank cell always means "this run did not retrieve it". */
  var rows = '';
  SOCIAL_FIELDS.forEach(function (field) {
    var value = d[field.key];
    if (value === null || value === undefined || value === '' ||
        (Array.isArray(value) && !value.length) ||
        (field.type === 'bool' && !value)) {
      return;
    }
    rows += '<tr><td class="dim">' + escapeHtml(field.label) + '</td><td>' +
            socialCell(field, value) + '</td></tr>';
  });
  if (rows) {
    html += '<table class="res-table"><tbody>' + rows + '</tbody></table>';
  } else if (!d.error) {
    html += '<p class="dim">No profile fields retrieved.</p>';
  }

  if (d.posts && d.posts.length) {
    html += '<h4>Posts (' + d.posts.length + ')</h4><ul class="post-list">';
    d.posts.slice(0, 12).forEach(function (post) {
      var href = safeHref(post.url || '');
      var caption = escapeHtml(post.caption || '(no caption)');
      var meta = [];
      if (post.likes !== undefined && post.likes !== null) meta.push(pluralize(post.likes, 'like'));
      if (post.comments !== undefined && post.comments !== null) meta.push(pluralize(post.comments, 'comment'));
      if (post.timestamp) meta.push(escapeHtml(String(post.timestamp).slice(0, 10)));
      html += '<li>' + (href ? '<a href="' + escapeHtml(href) + '" target="_blank" rel="noopener">' +
                          caption + '</a>' : caption);
      if (meta.length) html += ' <span class="dim">(' + escapeHtml(meta.join(' · ')) + ')</span>';
      html += '</li>';
    });
    html += '</ul>';
  }
  return html;
}

/* Session state, what the platform refused to return, and collection
   counters: operator diagnostics, not findings. They live in Details. */
function renderSocialDetails(d) {
  if (!d || d.error) return '';
  var html = '';
  /* Logged-out in red reads as failure — but for keyless platforms no
     session can or should exist, so say so plainly instead. */
  var keyless = (typeof SOCIAL_META !== 'undefined') && SOCIAL_META &&
    SOCIAL_META[d.platform] && !SOCIAL_META[d.platform].browser;
  if (d.logged_in) {
    html += renderStatusLine('Session', 'burner logged in', true);
  } else if (keyless) {
    html += '<p class="res-line dim">Session: none needed (keyless)</p>';
  } else {
    html += renderStatusLine('Session', 'logged out', false);
  }
  html += renderStatusLine('Source', d.source || 'n/a', !!d.source);

  /* Walls are the honest counterpart of an empty list. */
  var walls = d.walls || {};
  Object.keys(walls).forEach(function (kind) {
    html += renderStatusLine(walls[kind].label || kind, walls[kind].why || 'unavailable', false);
  });

  if (d.metrics && Object.keys(d.metrics).length) {
    html += '<span class="result-subtitle">Collected</span>';
    Object.keys(d.metrics).sort().forEach(function (name) {
      html += renderStatusLine(name.replace(/_/g, ' '), d.metrics[name], true);
    });
  }

  if (d.notes && d.notes.length) {
    html += '<span class="result-subtitle">Notes</span>';
    d.notes.forEach(function (note) {
      html += '<p class="res-line">' + escapeHtml(note) + '</p>';
    });
  }
  return html;
}

/* ── Platform shortcut tabs: three entries, one shared panel ──
 *
 * The sidebar tab IS the picker — there is no platform dropdown in the
 * form (it used to duplicate the tabs and disagree with them). The active
 * tab writes its key into the hidden #socialPlatform field, updates the
 * name line + placeholder + capability hint, and the submit handler reads
 * that field back. Unknown keys are remembered until the registry answers
 * so an early click never silently runs the wrong platform. */
var pendingSocialPlatform = null;
var SOCIAL_LABELS = {};
var SOCIAL_META = {};
/* Pre-registry display labels, for the moment between a click and the
   registry fetch resolving. Derived labels (capitalize(key)) read wrong
   for GitHub; this map only ever paints a name, never gates behaviour. */
var SOCIAL_FALLBACK_LABELS = {
  instagram: 'Instagram', mastodon: 'Mastodon', bluesky: 'Bluesky',
  github: 'GitHub', gitlab: 'GitLab', keybase: 'Keybase'
};

function socialLabel(key) {
  return SOCIAL_LABELS[key] || SOCIAL_FALLBACK_LABELS[key] || key;
}

function selectSocialPlatform(key) {
  var sel = document.getElementById('socialPlatform');
  if (!sel) { pendingSocialPlatform = key; return; }
  /* The click wins immediately, registry answered or not: the hidden
     field is what submit reads, so deferring it until the list arrives
     let a fast click run the *previous* platform silently. An unknown
     platform submits too — the server names the gap, honestly. */
  sel.value = key;
  pendingSocialPlatform = null;
  var name = document.getElementById('socialPlatformName');
  if (name) name.textContent = socialLabel(key);
  setSocialPlaceholder(key);
  updateSocialCaps(null);
  /* The tab *is* the dashboard: switching platforms re-resolves that
     platform's tracked target and repaints stats/diff/history. */
  loadSocialDashboard(key);
}

function setSocialPlaceholder(key) {
  var input = document.getElementById('socialHandle');
  if (!input) return;
  var hints = {
    instagram: 'instagram username',
    mastodon: 'user or user@instance',
    bluesky: 'user.bsky.social',
    github: 'github username or org',
    gitlab: 'gitlab username or org',
    keybase: 'keybase username'
  };
  input.placeholder = hints[key] || 'handle';
}

/* ── Platform list (registry-driven) ── */
function loadSocialPlatforms() {
  var sel = document.getElementById('socialPlatform');
  var caps = document.getElementById('socialCaps');
  if (!sel) return;
  apiFetch('/api/social/platforms')
    .then(function (r) { return r.json(); })
    .then(function (list) {
      if (!Array.isArray(list) || !list.length) {
        sel.value = '';
        if (caps) caps.textContent = 'No platform importable — the social engine failed to load.';
        return;
      }
      SOCIAL_LABELS = {};
      SOCIAL_META = {};
      list.forEach(function (p) {
        SOCIAL_LABELS[p.key] = p.label || p.key;
        SOCIAL_META[p.key] = { browser: p.browser !== false, login: p.login || 'none' };
      });
      /* The operator's explicit choice wins over any default. When the
         registry does not know that platform (an older server process
         behind this UI, or a broken adapter), the form stays on the
         requested platform and showCaps names the mismatch — falling
         back to another platform's form silently is how Instagram's
         config ends up under a GitHub tab. */
      var want = pendingSocialPlatform || sel.value || 'instagram';
      pendingSocialPlatform = null;
      sel.value = want;
      var name = document.getElementById('socialPlatformName');
      if (name) name.textContent = socialLabel(want);
      setSocialPlaceholder(want);
      showCaps(list, want);
      /* The Targets add-form rides the same registry: one source of
         platform truth for every picker in the app. */
      var targetSel = document.getElementById('targetPlatform');
      if (targetSel) {
        var keep = targetSel.value;
        targetSel.innerHTML = list.map(function (p) {
          return '<option value="' + escapeHtml(p.key) + '">' +
            escapeHtml(p.label || p.key) + '</option>';
        }).join('');
        if (keep) targetSel.value = keep;
      }
    })
    .catch(function () {
      /* A failed registry fetch must not blank the operator's explicit
         choice — the form stays on the selected platform and the caps
         line names why there is no capability header. */
      if (caps) caps.textContent = 'Could not reach the platform registry — capabilities unknown; your selection stays. Check the server, then reload.';
    });
}

function updateSocialCaps(platforms) {
  var caps = document.getElementById('socialCaps');
  var sel = document.getElementById('socialPlatform');
  if (!caps || !sel || !sel.value) return;
  if (!platforms) {
    return apiFetch('/api/social/platforms').then(function (r) { return r.json(); })
      .then(function (list) { showCaps(list, sel.value); })
      .catch(function () {
        /* A tab click that cannot reach the registry must explain itself
           rather than reject into the console — and must not blank the
           operator's selection. */
        var el = document.getElementById('socialCaps');
        if (el) el.textContent = 'Could not reach the platform registry — capabilities unknown; your selection stays.';
      });
  }
  showCaps(platforms, sel.value);
}

function showCaps(platforms, key) {
  var caps = document.getElementById('socialCaps');
  if (!caps) return;      var match = (platforms || []).filter(function (p) { return p.key === key; })[0];
      var keyless = !!match && match.browser === false;
      var form = document.getElementById('form-social');
      var browserOpts = form ? form.querySelectorAll('[data-browser-only]') : [];
      /* Headless / Deep / Download Media drive the stealth browser, which
         keyless adapters never launch — offering them there implies stories
         and media downloads that do not exist on those tabs. An unknown
         platform hides them too: we cannot claim what it needs, and a
         generic form is safer than one tuned for a different platform.
         The burner itself lives in Settings now (it is account config, not
         target config), so there is no row here to toggle. */
  for (var i = 0; i < browserOpts.length; i++) {
    browserOpts[i].style.display = (match && !keyless) ? '' : 'none';
  }
  if (!match) {
    /* A tab this server's registry does not know: say so. An older
       process since an upgrade or a disabled adapter must be readable
       from the panel, not distinguishable from a working tab. */
    caps.textContent = "'" + key + "' is not in this server's registry " +
      "(older process since an upgrade, or a broken adapter) — restart " +
      "the server so every bundled adapter registers.";
    return;
  }
  caps.textContent = 'Can return: ' + match.capabilities.join(', ') +
    (match.login === 'none' ? (match.browser === false ? ' · keyless, no browser needed' : ' · no burner login') : ' · burner login supported');
}

function renderSection(title, inner, tool, badge) {
  if (!inner) return '';
  var badgeHtml = '';
  if (badge && badge.text) {
    badgeHtml = '<span class="person-conf person-conf-' +
      personConfidence(badge.confidence) + '">' + escapeHtml(badge.text) + '</span>';
  }
  return '<div class="res-section"><div class="res-section-head">' +
         '<span class="res-section-title">' + escapeHtml(title) + '</span>' +
         '<span class="res-section-meta">' + badgeHtml +
         (tool ? '<span class="result-tool">' + escapeHtml(tool) + '</span>' : '') +
         '</span></div>' + inner + '</div>';
}

function renderKv(obj, labels) {
  var keys = Object.keys(obj).filter(function (k) {
    var v = obj[k];
    return v !== null && v !== undefined && v !== '' &&
           typeof v !== 'object';
  });
  if (!keys.length) return '';
  var html = '<table class="kv-table"><tbody>';
  keys.forEach(function (k) {
    var label = (labels && labels[k]) || k.replace(/_/g, ' ');
    html += '<tr><th>' + escapeHtml(label) + '</th><td>' + escapeHtml(String(obj[k])) + '</td></tr>';
  });
  return html + '</tbody></table>';
}

function renderChips(items, cap) {
  if (!items || !items.length) return '';
  var rows = items.slice(0, cap || 60);
  var html = '<div class="chip-group">';
  rows.forEach(function (item) {
    html += '<span class="chip">' + escapeHtml(String(item)) + '</span>';
  });
  html += '</div>';
  if (items.length > rows.length) {
    html += '<p class="dim">+ ' + (items.length - rows.length) + ' more in raw JSON</p>';
  }
  return html;
}

/* ── Normalized facts block (spyglass_pro.facts) ──
 *
 * Every engine answers in its own shape; facts.normalize derives one
 * stable entities/facts block per run. This renders it at the top of
 * every result so the skimmable answer no longer hides inside the
 * per-engine sections below. Absent block = render nothing: an errored
 * or pre-facts run must not gain an empty "findings" section.
 * Medium-confidence facts are badged, never hidden — agreement-derived
 * counts are weaker evidence than direct third-party values. */
function renderNormalized(block) {
  if (!block || typeof block !== 'object') return '';
  var facts = Array.isArray(block.facts) ? block.facts : [];
  var entities = Array.isArray(block.entities) ? block.entities : [];
  if (!facts.length && !entities.length) return '';
  var html = '<div class="res-section facts-block"><span class="res-section-title">Key findings</span>';
  if (facts.length) {
    html += '<table class="kv-table facts-table"><tbody>';
    facts.forEach(function (f) {
      if (!f || typeof f !== 'object') return;
      var val = f.value;
      var cell = (typeof val === 'boolean') ? (val ? 'yes' : 'no')
        : (typeof val === 'number' && isFinite(val)) ? val.toLocaleString()
        : escapeHtml(String(val === null || val === undefined ? '—' : val));
      var conf = (f.confidence && f.confidence !== 'high')
        ? ' <span class="fact-conf fact-conf-medium">' + escapeHtml(String(f.confidence)) + '</span>' : '';
      html += '<tr><th>' + escapeHtml(String(f.label || f.key || 'fact')) + '</th><td>' + cell +
              ' <span class="dim">· ' + escapeHtml(String(f.source || '')) + '</span>' + conf + '</td></tr>';
    });
    html += '</tbody></table>';
  } else {
    html += '<p class="dim">No discrete findings — see sections below.</p>';
  }
  if (entities.length) {
    var byKind = {};
    entities.forEach(function (e) {
      if (!e || e.value === undefined) return;
      var kind = String(e.kind || 'other');
      (byKind[kind] = byKind[kind] || []).push(String(e.value));
    });
    html += '<span class="res-section-title">Related entities</span>';
    Object.keys(byKind).sort().forEach(function (kind) {
      var vals = byKind[kind].filter(function (v, i, a) { return a.indexOf(v) === i; });
      html += '<p class="res-line dim">' + escapeHtml(kind) + ' (' + vals.length + ')</p>' +
              renderChips(vals, 24);
    });
  }
  if (block.provenance && block.provenance.engine) {
    html += '<p class="dim">via ' + escapeHtml(String(block.provenance.engine)) + '</p>';
  } else if (block.engine) {
    html += '<p class="dim">via ' + escapeHtml(String(block.engine)) + '</p>';
  }
  return html + '</div>';
}

function renderLinkTable(items, limit) {
  if (!items || !items.length) return '';
  var rows = items.slice(0, limit || 50);
  var html = '<table class="res-table"><thead><tr><th>Platform</th><th>URL</th></tr></thead><tbody>';
  rows.forEach(function (item) {
    var domain = item.domain || item.name || item.url || item;
    var url = item.url || item.link || '';
    var href = url ? safeHref(url) : '';
    var cell;
    if (href) {
      cell = '<a href="' + escapeHtml(href) + '" target="_blank" rel="noopener">' + escapeHtml(url) + '</a>';
    } else if (url) {
      cell = '<span class="dim">' + escapeHtml(url) + '</span>';
    } else {
      cell = '<span class="dim">—</span>';
    }
    html += '<tr><td>' + escapeHtml(domain) + '</td><td>' + cell + '</td></tr>';
  });
  if (items.length > rows.length) {
    html += '<tr><td colspan="2" class="dim">+ ' + (items.length - rows.length) + ' more in raw JSON</td></tr>';
  }
  return html + '</tbody></table>';
}

function renderBreach(b) {
  if (!b || typeof b !== 'object') return '';
  var sources = b.sources || [];
  var fields = b.fields || [];
  var found = b.found;
  if (!sources.length && !fields.length && found === undefined) return '';
  var html = '';
  if (found !== undefined) {
    html += '<p class="res-line"><strong>' + escapeHtml(String(found)) + '</strong> record(s) exposed</p>';
  }
  if (sources.length) {
    html += '<table class="res-table"><thead><tr><th>Source</th><th>Date</th></tr></thead><tbody>';
    sources.forEach(function (s) {
      html += '<tr><td>' + escapeHtml(s.name || String(s)) + '</td><td>' + escapeHtml(s.date || '—') + '</td></tr>';
    });
    html += '</tbody></table>';
  }
  if (fields.length) {
    html += '<p class="res-line dim">Fields exposed:</p>' + renderChips(fields);
  }
  return html;
}

function renderStatusLine(label, value, good) {
  return '<p class="res-line">' + escapeHtml(label) + ': <span class="status-' +
         (good ? 'ok' : 'err') + '">' + escapeHtml(String(value)) + '</span></p>';
}

/* ── Accounts: one table, one row per account, the tool in its own column ──
 *
 * The old renderer split accounts into "user-scanner only", "3 of 4 (no
 * blackbird)" … — a map of which engine ran, not of what was found. What
 * the operator needs is the account and the engine(s) behind it; that is a
 * column, not a section hierarchy. Single-source rows stay visibly
 * single-source so a lone hit never reads like a four-engine agreement. */
function renderAccountTable(rows) {
  var shown = rows.slice(0, 100);
  var html = '<table class="res-table results-table"><thead><tr>' +
             '<th>Account</th><th>URL</th><th>Found by</th>' +
             '</tr></thead><tbody>';
  shown.forEach(function (r) {
    var url = r.url || '';
    var href = url ? safeHref(url) : '';
    var link = href
      ? '<a href="' + escapeHtml(href) + '" target="_blank" rel="noopener">' +
        escapeHtml(url) + '</a>'
      : (url ? '<span class="dim">' + escapeHtml(url) + '</span>'
             : '<span class="dim">—</span>');
    html += '<tr><td>' + escapeHtml(r.domain || '') + '</td><td>' + link +
            '</td><td><span class="result-tool">' + escapeHtml(r.tool || '—') +
            '</span></td></tr>';
  });
  if (rows.length > shown.length) {
    html += '<tr><td colspan="3" class="dim">+ ' + (rows.length - shown.length) +
            ' more in Raw JSON</td></tr>';
  }
  return html + '</tbody></table>';
}

function accountRows(buckets, data) {
  var rows = [];
  buckets.forEach(function (bucket) {
    (data[bucket[0]] || []).forEach(function (a) {
      rows.push({ domain: a.domain || a.name || a.url || '',
                  url: a.url || '',
                  tool: (a.engines && a.engines.length)
                    ? a.engines.join(' + ') : bucket[1] });
    });
  });
  return rows;
}

var EMAIL_BUCKETS = [
  ['both', '2+ engines'],
  ['user_scanner_only', 'user-scanner'],
  ['holehe_only', 'holehe'],
  ['blackbird_only', 'blackbird']
];

/* ── Spyglass-OSINT: email ── */
function renderEmail(d) {
  var rows = accountRows(EMAIL_BUCKETS, d);
  var html = '';
  if (rows.length) {
    html += renderSection('Accounts (' + rows.length + ')',
                          renderAccountTable(rows), 'email engines');
  }
  if (d.breach) html += renderSection('Breach check', renderBreach(d.breach), 'breach');
  return html || renderGeneric(d);
}

/* Bucket key → the exact engines that had to agree for a row to land there.
   Naming all four on an all_4 row is evidence, not decoration. */
var USERNAME_BUCKETS = [
  ['all_4', 'user-scanner + sherlock + maigret + blackbird'],
  ['all_3_no_bb', 'user-scanner + sherlock + maigret'],
  ['all_3_no_mg', 'user-scanner + sherlock + blackbird'],
  ['all_3_no_sh', 'user-scanner + maigret + blackbird'],
  ['all_3_no_us', 'sherlock + maigret + blackbird'],
  ['us+sherlock', 'user-scanner + sherlock'],
  ['us+maigret', 'user-scanner + maigret'],
  ['us+blackbird', 'user-scanner + blackbird'],
  ['sherlock+maigret', 'sherlock + maigret'],
  ['sherlock+blackbird', 'sherlock + blackbird'],
  ['maigret+blackbird', 'maigret + blackbird'],
  ['us_only', 'user-scanner'],
  ['sherlock_only', 'sherlock'],
  ['maigret_only', 'maigret'],
  ['blackbird_only', 'blackbird']
];

/* ── Spyglass-OSINT: username ── */
function renderUsername(d) {
  var rows = accountRows(USERNAME_BUCKETS, d);
  var html = '';
  if (rows.length) {
    html += renderSection('Accounts (' + rows.length + ')',
                          renderAccountTable(rows), 'username engines');
  }
  if (d.breach) html += renderSection('Breach check', renderBreach(d.breach), 'breach');
  return html || renderGeneric(d);
}

/* ── Spyglass-OSINT: phone ── */
function renderPhone(d) {
  var html = '';
  if (d.phonenumbers) {
    html += renderSection('Number analysis', renderKv(d.phonenumbers, {
      valid: 'Valid', country_code: 'Country code', region: 'Region',
      location: 'Location', carrier: 'Carrier', timezone: 'Timezone',
      type: 'Line type', e164: 'E.164', international: 'International',
      national: 'National'
    }), 'phonenumbers');
  }
  if (d.phoneinfoga && Object.keys(d.phoneinfoga).length) {
    html += renderSection('PhoneInfoga', renderKv(d.phoneinfoga), 'PhoneInfoga');
  }
  if (Array.isArray(d.ignorant) && d.ignorant.length) {
    html += renderSection('Web mentions', renderLinkTable(
      d.ignorant.map(function (u) { return { domain: u, url: u }; }), 20), 'ignorant');
  }
  if (d.breach) html += renderSection('Breach check', renderBreach(d.breach), 'breach');
  return html || renderGeneric(d);
}

/* ── Spyglass-OSINT: website (light: owner / DNS / CT) ── */
function renderWebsite(d) {
  var html = '';
  if (d.whois) html += renderSection('WHOIS', renderKv(d.whois), 'whois');
  if (d.dns_records) html += renderSection('DNS records', renderKv(d.dns_records), 'dig');
  if (d.dns_email_security) {
    html += renderSection('DNS email security', renderKv(d.dns_email_security), 'dig');
  }
  if (d.wildcard_dns) html += renderSection('Wildcard DNS', renderKv(d.wildcard_dns), 'dig');
  if (Array.isArray(d.ct) && d.ct.length) {
    html += renderSection('Certificate transparency (' + d.ct.length + ')',
                          renderChips(d.ct), 'crt.sh');
  }
  html += renderGeneric(d, ['whois', 'dns_records', 'dns_email_security',
                            'wildcard_dns', 'ct']);
  return html;
}

/* ── Spyglass-OSINT: darkweb ── */
function renderDarkweb(d) {
  var html = '';
  if (Array.isArray(d.ahmia) && d.ahmia.length) {
    html += renderSection('Ahmia index hits (' + d.ahmia.length + ')',
      renderLinkTable(d.ahmia.map(function (h) {
        return { domain: h.title || h.name || h, url: h.url || h.link || '' };
      }), 20), 'Ahmia');
  } else if (d.ahmia) {
    html += renderSection('Ahmia index',
      renderStatusLine('Result', 'no hits', false), 'Ahmia');
  }
  if (d.breach) html += renderSection('Breach check', renderBreach(d.breach), 'breach');
  if (d.pwned !== undefined) {
    html += renderSection('Have I Been Pwned',
      renderStatusLine('Result', d.pwned ? 'PWNED (' + d.count + ' breaches)' : 'not found',
                       !d.pwned), 'HIBP');
  }
  html += renderGeneric(d, ['ahmia', 'breach', 'pwned', 'count', 'query', 'type']);
  return html;
}

/* ── Spyglass-OSINT: opsec ── */
function renderOpsec(d) {
  var html = '';
  if (d.direct) {
    html += renderSection('Direct connection (no proxy)', renderKv(d.direct), 'opsec');
  }
  if (d.proxy_configured !== undefined) {
    html += renderStatusLine('Proxy configured', d.proxy_configured ? 'yes' : 'no', !!d.proxy_configured);
  }
  if (d.dns_leak) {
    html += renderStatusLine('DNS leak', d.dns_leak, d.dns_leak === 'not_applicable');
  }
  if (Array.isArray(d.recommendations) && d.recommendations.length) {
    html += renderSection('Recommendations',
      '<ul class="res-list">' + d.recommendations.map(function (r) {
        return '<li>' + escapeHtml(r) + '</li>';
      }).join('') + '</ul>', 'opsec');
  }
  html += renderGeneric(d, ['direct', 'proxy_configured', 'dns_leak', 'recommendations']);
  return html;
}

/* ── Cross-tool investigation ──
 *
 * A resolved run leads with the person card: identity, accounts, breaches,
 * links and conflicts. The module payloads, correlator index and social
 * diagnostics move into Details. Legacy stored runs (no `person` block)
 * keep the older entities-first layout.
 *
 * Matches sort first in the legacy layout: they are the verdict, info rows
 * are context. The graph is a summary visual only — center is the queried
 * input, ring nodes are entity kinds with real counts, nothing weighted. */
function renderInvestigate(d) {
  if (d.person && typeof d.person === 'object') return renderPerson(d);
  var html = renderCorrelatorSections(d);
  html += renderModuleSections(d, false);
  html += renderGeneric(d, ['inputs', 'entities', 'correlations', 'results',
                            'ip_recon', 'social', 'progress', 'summary',
                            'person', 'person_error']);
  return html;
}

function renderCorrelatorSections(d, entityLabel, compact) {
  var html = '';
  var matchValues = [];
  (d.correlations || []).forEach(function (c) {
    if (c && c.type === 'match' && c.detail) {
      String(c.detail).split(',').forEach(function (v) {
        v = v.trim();
        if (v && matchValues.indexOf(v) === -1) matchValues.push(v);
      });
    }
  });
  if (d.entities) {
    if (compact) {
      /* Under a person card the graph is already on the face as Accounts
       * and Links; a second diagram in Details just repeats it. Keep the
       * entity index as a compact grid. */
      var entGrid = personIdentityGrid([
        ['Emails', d.entities.emails], ['Domains', d.entities.domains],
        ['IP addresses', d.entities.ips], ['Phones', d.entities.phones],
        ['Organizations', d.entities.orgs], ['ASNs', d.entities.asns],
        ['Regions', d.entities.regions],
      ]);
      if (entGrid) {
        html += renderSection(entityLabel || 'Entities', entGrid, 'correlator');
      }
    } else {
      var entHtml = renderEntityGraph(d);
      [['emails', 'Emails'], ['domains', 'Domains'], ['ips', 'IP addresses'],
       ['phones', 'Phone numbers'], ['orgs', 'Organizations'], ['asns', 'ASNs']].forEach(function (pair) {
        var values = d.entities[pair[0]];
        if (Array.isArray(values) && values.length) {
          entHtml += '<p class="res-line dim">' + pair[1] + ':</p>' + matchChips(values, matchValues);
        }
      });
      html += renderSection(entityLabel || 'Entities', entHtml, 'correlator');
    }
  }
  if (Array.isArray(d.correlations) && d.correlations.length) {
    var corrs = d.correlations.slice().sort(function (a, b) {
      return ((b && b.type === 'match') - (a && a.type === 'match'));
    });
    var matches = corrs.filter(function (c) { return c && c.type === 'match'; }).length;
    var title = 'Correlations (' + corrs.length + (matches ? ', ' + matches + ' match' +
      (matches === 1 ? '' : 'es') : '') + ')';
    if (compact) {
      var rows = corrs.map(function (c) {
        var isMatch = c && c.type === 'match';
        return '<li class="person-link">' +
          '<span class="person-conf ' +
          (isMatch ? 'person-conf-high' : 'person-conf-unconfirmed') + '">' +
          escapeHtml(isMatch ? 'match' : 'info') + '</span>' +
          '<span class="person-link-body"><span class="person-link-desc">' +
          escapeHtml(c.desc || c.type || '') + '</span>' +
          (c.detail ? '<span class="person-link-detail">' +
            escapeHtml(String(c.detail)) + '</span>' : '') +
          '</span></li>';
      }).join('');
      html += renderSection(title, '<ul class="person-links">' + rows + '</ul>', 'correlator');
    } else {
      html += renderSection(title,
        '<ul class="res-list corr-list">' + corrs.map(function (c) {
          var isMatch = c.type === 'match';
          var out = '<li class="' + (isMatch ? 'corr-match' : '') + '">' +
            (isMatch ? '<span class="artifact-kind">match</span> ' : '') +
            '<strong>' + escapeHtml(c.desc || c.type || '') + '</strong>';
          if (c.detail) out += '<br>' + corrDetailChips(String(c.detail), isMatch);
          return out + '</li>';
        }).join('') + '</ul>', 'correlator');
    }
  }
  return html;
}

function renderModuleSections(d, includeSocialDetails) {
  var html = '';
  if (d.results && typeof d.results === 'object') {
    Object.keys(d.results).forEach(function (key) {
      var sub = d.results[key];
      if (!sub || typeof sub !== 'object' || sub.error) return;
      html += renderSection(key, renderBody(sub, key), 'spyglass');
    });
  }
  if (d.social && !d.social.error) {
    var socialLabel = (d.social.platform || 'social').toUpperCase();
    html += renderSection(socialLabel + ' profile', renderBody(d.social, 'social'), 'social');
    if (includeSocialDetails) html += renderSocialDetails(d.social);
  }
  return html;
}

/* ── Person card ──
 *
 * Values carry their source, and confidence is shown, never implied. A
 * website's WHOIS data sits in its own context block because it describes
 * the domain until a value matches an anchor. */
function personConfidence(value) {
  var conf = String(value || 'unconfirmed').toLowerCase();
  return ['high', 'medium', 'possible', 'unconfirmed'].indexOf(conf) !== -1
    ? conf : 'unconfirmed';
}

function personEntryChips(items) {
  if (!Array.isArray(items) || !items.length) return '';
  var html = '<div class="person-values">';
  items.forEach(function (item) {
    var value = item;
    var source = '';
    var confidence = '';
    var context = false;
    if (item && typeof item === 'object') {
      value = item.value;
      source = item.source || '';
      confidence = item.confidence || '';
      context = !!item.context;
    }
    if (value === null || value === undefined || value === '') return;
    var meta = [];
    if (source) meta.push(source);
    if (confidence === 'possible' || confidence === 'medium') meta.push(confidence);
    if (context) meta.push('context');
    html += '<span class="person-value">' +
            '<span class="chip">' + escapeHtml(String(value)) + '</span>' +
            (meta.length ? '<span class="person-source">' +
              escapeHtml(meta.join(' · ')) + '</span>' : '') +
            '</span>';
  });
  return html + '</div>';
}

/* Identity and context share one compact two-column grid. A table here
 * made every value a full-width row with its own provenance line; the
 * grid keeps the same information at roughly half the height. */
function personIdentityGrid(pairs) {
  var html = '';
  pairs.forEach(function (pair) {
    var values = personEntryChips(pair[1]);
    if (!values) return;
    html += '<div class="person-identity-item">' +
            '<span class="person-identity-label">' + escapeHtml(pair[0]) + '</span>' +
            values + '</div>';
  });
  return html ? '<div class="person-identity-grid">' + html + '</div>' : '';
}

function renderPerson(d) {
  var p = d.person || {};
  var confidence = personConfidence(p.confidence);
  var html = '';

  var identity = personIdentityGrid([
    ['Names', p.names], ['Handles', p.handles], ['Emails', p.emails],
    ['Phones', p.phones], ['Locations', p.locations],
    ['Organizations', p.organizations], ['Domains', p.domains],
    ['Websites', p.websites],
  ]);
  if (identity) {
    html += renderSection('Identity', identity, 'correlator', {
      text: confidence,
      confidence: confidence,
    });
  }

  var accounts = Array.isArray(p.accounts) ? p.accounts : [];
  if (accounts.length) {
    var shown = accounts.slice(0, 50);
    var table = '<table class="res-table person-accounts"><thead><tr>' +
                '<th>Account</th><th>Linked by</th><th>Found by</th>' +
                '</tr></thead><tbody>';
    shown.forEach(function (a) {
      var url = String(a.url || '');
      var href = url ? safeHref(url) : '';
      var urlLine = href
        ? '<a class="person-account-url" href="' + escapeHtml(href) +
          '" target="_blank" rel="noopener" title="' + escapeHtml(url) + '">' +
          escapeHtml(url) + '</a>'
        : (url ? '<span class="person-account-url dim" title="' + escapeHtml(url) + '">' +
                 escapeHtml(url) + '</span>' : '');
      var tools = (a.tools || []).map(function (tool) {
        return '<span class="result-tool">' + escapeHtml(tool) + '</span>';
      }).join(' ');
      var evidence = personConfidence(a.confidence);
      table += '<tr><td><div class="person-account-name">' +
               '<span class="person-account-platform">' + escapeHtml(a.platform || '') +
               '</span><span class="person-evidence person-evidence-' + evidence +
               '" title="Account confidence">' +
               escapeHtml(evidence) + '</span></div>' + urlLine + '</td><td>' +
               escapeHtml((a.via || []).join(' + ')) + '</td><td>' +
               (tools || '<span class="dim">—</span>') + '</td></tr>';
    });
    if (accounts.length > shown.length) {
      table += '<tr><td colspan="3" class="dim">+ ' + (accounts.length - shown.length) +
               ' more in Raw JSON</td></tr>';
    }
    table += '</tbody></table>';
    html += renderSection('Accounts (' + accounts.length + ')', table);
  }

  var breaches = Array.isArray(p.breaches) ? p.breaches : [];
  if (breaches.length) {
    var btable = '<table class="res-table person-breaches"><thead><tr>' +
                 '<th>Source</th><th>Date</th><th>Via</th></tr></thead><tbody>';
    breaches.forEach(function (b) {
      var name = String(b.name || 'unknown');
      if (b.count) name += ' (' + b.count + ' records)';
      btable += '<tr><td>' + escapeHtml(name) + '</td><td>' +
                escapeHtml(b.date || '—') + '</td><td>' +
                escapeHtml((b.via || []).join(', ') || '—') + '</td></tr>';
    });
    btable += '</tbody></table>';
    if (Array.isArray(p.exposed_fields) && p.exposed_fields.length) {
      btable += '<p class="person-caption">Exposed fields: ' +
                escapeHtml(p.exposed_fields.join(', ')) + '</p>';
    }
    html += renderSection('Breaches (' + breaches.length + ')', btable, 'breach');
  }

  var links = Array.isArray(p.links) ? p.links : [];
  if (links.length) {
    var confirmed = links.filter(function (l) { return l.confidence === 'high'; }).length;
    var list = '<ul class="person-links">' + links.map(function (l) {
      var conf = personConfidence(l.confidence);
      return '<li class="person-link">' +
        '<span class="person-conf person-conf-' + conf + '">' + escapeHtml(conf) +
        '</span><span class="person-link-body">' +
        '<span class="person-link-desc">' + escapeHtml(l.desc || '') + '</span>' +
        (l.detail ? '<span class="person-link-detail">' +
          escapeHtml(String(l.detail)) + '</span>' : '') +
        '</span></li>';
    }).join('') + '</ul>';
    html += renderSection('Links (' + links.length +
      (confirmed ? ', ' + confirmed + ' confirmed' : '') + ')', list, 'correlator');
  }

  var conflicts = Array.isArray(p.conflicts) ? p.conflicts : [];
  if (conflicts.length) {
    var clist = '<ul class="person-links">' + conflicts.map(function (c) {
      var values = Array.isArray(c.values) ? c.values : [];
      return '<li class="person-link person-conflict-row">' +
        '<span class="person-conf person-conf-possible">' +
        escapeHtml(c.kind || 'conflict') + '</span>' +
        '<span class="person-link-body"><span class="person-link-desc">' +
        escapeHtml(c.desc || '') + '</span>' +
        (values.length ? '<span class="person-link-detail">' +
          escapeHtml(values.join(' · ')) + '</span>' : '') +
        '</span></li>';
    }).join('') + '</ul>';
    html += renderSection('Conflicts (' + conflicts.length + ')', clist, 'correlator');
  }

  var context = p.context || {};
  var contextGrid = personIdentityGrid([
    ['Organizations', context.organizations], ['Names', context.names],
    ['Emails', context.emails], ['Phones', context.phones],
    ['Locations', context.locations],
  ]);
  if (contextGrid) {
    var lead = context.website
      ? 'WHOIS data describes ' + context.website + ', not necessarily the person.'
      : 'WHOIS data describes the domain, not necessarily the person.';
    html += renderSection('Domain context',
      '<p class="person-caption">' + escapeHtml(lead) + '</p>' + contextGrid,
      'whois');
  }

  if (!html) {
    html = '<p class="dim">No identity signals resolved from this run.</p>';
  }
  return html;
}

function renderInvestigateDetails(d) {
  if (!d || !d.person || typeof d.person !== 'object') return '';
  var html = renderCorrelatorSections(d, 'Entity index', true);
  html += renderModuleSections(d, true);
  var notes = Array.isArray(d.person.notes) ? d.person.notes : [];
  if (notes.length) {
    html += '<span class="result-subtitle">Identity notes</span>';
    notes.forEach(function (note) {
      html += '<p class="res-line">' + escapeHtml(note) + '</p>';
    });
  }
  return html;
}

/* Entity chips with cross-leg matches lit up: a value the correlator
 * confirmed gets the accent border plus a title saying so. Exact string
 * match only — near-matches stay plain rather than implying a link. */
function matchChips(values, matchValues) {
  if (!values || !values.length) return '';
  var html = '<div class="chip-group">';
  values.forEach(function (v) {
    var hot = matchValues && matchValues.indexOf(String(v)) !== -1;
    html += hot ? '<span class="chip chip-match" title="confirmed by a cross-leg match">' +
                  escapeHtml(String(v)) + '</span>'
                : '<span class="chip">' + escapeHtml(String(v)) + '</span>';
  });
  return html + '</div>';
}

/* A correlation detail is one value ("x.com") or a joined few — chips
 * either way, capped so a five-address WHOIS dump stays readable. */
function corrDetailChips(detail, isMatch) {
  var parts = detail.split(',').map(function (v) { return v.trim(); })
    .filter(function (v) { return v; });
  if (!parts.length) return '<span class="dim">—</span>';
  var shown = parts.slice(0, 8);
  var html = '<div class="chip-group">' + shown.map(function (v) {
    return '<span class="chip' + (isMatch ? ' chip-match' : '') + '">' +
           escapeHtml(v) + '</span>';
  }).join('') + '</div>';
  if (parts.length > shown.length) {
    html += '<p class="dim">+ ' + (parts.length - shown.length) + ' more</p>';
  }
  return html;
}

/* Summary graph: queried input in the center, entity kinds on a ring
 * with their real counts. Kinds beyond six are listed, not drawn — a
 * seven-spoke SVG stops being readable. No weights, no inference. */
function renderEntityGraph(d) {
  var kinds = Object.keys(d.entities || {}).filter(function (k) {
    return Array.isArray(d.entities[k]) && d.entities[k].length;
  });
  if (kinds.length < 2) return '';
  var shown = kinds.slice(0, 6);
  var inputs = d.inputs && typeof d.inputs === 'object' ? d.inputs : null;
  var center = inputs ? Object.keys(inputs).map(function (k) { return inputs[k]; })
    .filter(function (v) { return v; }).join(', ') : '';
  center = String(center || 'target').slice(0, 28);
  var W = 420, H = 60 + shown.length * 34, cx = W / 2, cy = H / 2;
  var svg = '<div class="entity-graph"><svg viewBox="0 0 ' + W + ' ' + H + '" role="img" ' +
    'aria-label="Entity summary graph">';
  var n = shown.length;
  var pts = shown.map(function (kind, i) {
    var a = (i / n) * Math.PI * 2 - Math.PI / 2;
    return { kind: kind, x: cx + Math.cos(a) * 150, y: cy + Math.sin(a) * (H / 2 - 30) };
  });
  pts.forEach(function (p) {
    svg += '<line x1="' + cx + '" y1="' + cy + '" x2="' + p.x.toFixed(1) +
           '" y2="' + p.y.toFixed(1) + '" class="graph-edge"/>';
  });
  pts.forEach(function (p) {
    var count = d.entities[p.kind].length;
    svg += '<g><rect x="' + (p.x - 62).toFixed(1) + '" y="' + (p.y - 15).toFixed(1) +
           '" width="124" height="30" rx="8" class="graph-node"/>' +
           '<text x="' + p.x.toFixed(1) + '" y="' + (p.y + 4).toFixed(1) +
           '" text-anchor="middle" class="graph-label">' +
           escapeHtml(p.kind) + ' · ' + count + '</text></g>';
  });
  svg += '<g><rect x="' + (cx - 70) + '" y="' + (cy - 16) + '" width="140" height="32" rx="10" ' +
         'class="graph-center"/>' +
         '<text x="' + cx + '" y="' + (cy + 5) + '" text-anchor="middle" class="graph-center-label">' +
         escapeHtml(center) + '</text></g></svg>';
  if (kinds.length > shown.length) {
    svg += '<p class="dim">+ ' + (kinds.length - shown.length) + ' more kinds below</p>';
  }
  return svg + '</div>';
}

/* ── Generic fallback ── */
function renderGeneric(data, skip) {
  skip = skip || [];
  var html = '';
  Object.keys(data).forEach(function (key) {
    if (skip.indexOf(key) !== -1) return;
    /* The normalized block has its own renderer at the top of the card —
       dumping it again as generic key/value rows would double every fact. */
    if (key === 'progress' || key === 'summary' || key === 'artifacts' ||
        key === 'stored_run_id' || key === 'report_dir' || key === 'normalized') return;
    html += renderValue(data[key], key);
  });
  return html;
}

function renderValue(value, key) {
  if (value === null || value === undefined || value === '') return '';
  if (Array.isArray(value)) {
    if (!value.length) return '';
    if (value.every(function (v) { return typeof v === 'object' && v !== null && !Array.isArray(v); })) {
      var cols = Object.keys(value[0]);
      if (cols.length && cols.length <= 6 && cols.every(function (c) {
        return value.every(function (row) {
          var v = row[c];
          return v === null || v === undefined || ['string', 'number', 'boolean'].indexOf(typeof v) !== -1;
        });
      })) {
        return renderSection(key, '<table class="res-table"><thead><tr>' +
          cols.map(function (c) { return '<th>' + escapeHtml(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
          value.slice(0, 50).map(function (row) {
            return '<tr>' + cols.map(function (c) {
              return '<td>' + escapeHtml(String(row[c] === null || row[c] === undefined ? '—' : row[c])) + '</td>';
            }).join('') + '</tr>';
          }).join('') + '</tbody></table>');
      }
    }
    if (value.every(function (v) { return ['string', 'number', 'boolean'].indexOf(typeof v) !== -1; })) {
      return renderSection(key + ' (' + value.length + ')', renderChips(value.slice(0, 60)));
    }
    return renderSection(key, renderChips(value.slice(0, 20).map(function (v) {
      return typeof v === 'object' ? JSON.stringify(v) : String(v);
    })));
  }
  if (typeof value === 'object') {
    var keys = Object.keys(value);
    if (!keys.length) return '';
    var flat = keys.every(function (k) {
      var v = value[k];
      return v === null || v === undefined || ['string', 'number', 'boolean'].indexOf(typeof v) !== -1;
    });
    if (flat) return renderSection(key, renderKv(value));
    var html = '';
    keys.forEach(function (k) { html += renderValue(value[k], key + ' · ' + k); });
    return renderSection(key, html);
  }
  return renderSection(key, '<p class="res-line">' + escapeHtml(String(value)) + '</p>');
}

function copyResult(containerId) {
  var container = document.getElementById(containerId);
  if (!container) return;
  var pres = container.querySelectorAll('pre');
  var pre = pres[pres.length - 1];
  if (pre) {
    navigator.clipboard.writeText(pre.textContent).then(function () {
      showToast('Copied to clipboard', 'success');
    });
  }
}

function updateOverview(status) {
  if (!status) return;
  var tools = status.tools || {};
  var names = Object.keys(tools);
  var have = names.filter(function (k) { return tools[k]; }).length;
  var e = document.getElementById('statTools');
  if (e) e.textContent = names.length ? have + '/' + names.length : '—';
  var q = document.getElementById('statQueue');
  if (q && status.queue) q.textContent = status.queue.pending + '/' + status.queue.max_queue;
  renderToolGrid();
  apiFetch('/api/cases').then(function (r) { return r.json(); }).then(function (data) {
    var c = document.getElementById('statCases');
    if (c) c.textContent = Array.isArray(data) ? data.length : '—';
  }).catch(function () {});
  apiFetch('/api/settings').then(function (r) { return r.json(); }).then(function (data) {
    SETTINGS_CACHE = data || SETTINGS_CACHE;
    var k = document.getElementById('statKeys');
    if (k && data) k.textContent = (data.configured || 0) + '/' + (data.total || 0);
    renderToolGrid();
  }).catch(function () {});
}

/* ── Overview: per-tool data-source grid ──
 *
 * One coarse "engines online" number hides that each module leans on a
 * different set of tools — email needs 3, username 4, metadata 1. This
 * lists every module's actual legs with on/off dots, from the same
 * /api/status + vault snapshot the pre-flight check reads. */
var TOOL_ROWS = [
  { label: 'Email', tools: ['holehe', 'user-scanner', 'blackbird'], note: '+ breach data' },
  { label: 'Username', tools: ['user-scanner', 'sherlock', 'maigret', 'blackbird'], note: '+ breach data' },
  { label: 'Phone', tools: ['ignorant', 'phoneinfoga'], note: '+ breach data' },
  { label: 'Website', tools: ['dig', 'whois'], note: 'light: owner / DNS / CT' },
  { label: 'Dark web', keys: [['intelx_api_key', 'IntelX'], ['hibp_api_key', 'HIBP']], note: 'Ahmia + breach keyless' },
  { label: 'Metadata', tools: ['exiftool'] },
  { label: 'Social', platforms: true }
];

function renderToolGrid() {
  var grid = document.getElementById('toolGrid');
  if (!grid) return;
  var tools = (STATUS && STATUS.tools) || {};
  var platforms = (STATUS && STATUS.platforms) || [];
  grid.innerHTML = TOOL_ROWS.map(function (row) {
    var dots = '', frac = '';
    if (row.platforms) {
      var n = platforms.length;
      dots = '<span class="tool-dots"><i class="' + (n ? 'on' : 'off') + '" title="' + n + ' platform(s) registered"></i></span>';
      frac = n + ' platform' + (n === 1 ? '' : 's');
    } else if (row.tools) {
      var have = row.tools.filter(function (t) { return tools[t]; });
      dots = '<span class="tool-dots">' + row.tools.map(function (t) {
        return '<i class="' + (tools[t] ? 'on' : 'off') + '" title="' + escapeHtml(t) + (tools[t] ? ' detected' : ' missing') + '"></i>';
      }).join('') + '</span>';
      frac = have.length + '/' + row.tools.length;
    } else if (row.keys) {
      var known = row.keys.filter(function (spec) { return settingsKeySet(spec[0]) !== null; });
      var set = row.keys.filter(function (spec) { return settingsKeySet(spec[0]); });
      dots = '<span class="tool-dots">' + row.keys.map(function (spec) {
        var st = settingsKeySet(spec[0]);
        return '<i class="' + (st ? 'on' : 'off') + '" title="' + escapeHtml(spec[1]) + (st ? ' key set' : (st === null ? ' — open Settings' : ' key missing')) + '"></i>';
      }).join('') + '</span>';
      frac = known.length ? set.length + '/' + row.keys.length + ' keys' : '—';
    }
    return '<div class="tool-row"><span class="tool-row-name">' + escapeHtml(row.label) +
      (row.note ? ' <span class="tool-note">' + escapeHtml(row.note) + '</span>' : '') +
      '</span>' + dots + '<span class="tool-frac">' + escapeHtml(frac) + '</span></div>';
  }).join('');
}

/* ── Settings vault: masked read, write-only keys ── */
function loadSettings() {
  var grid = document.getElementById('settingsGrid');
  var status = document.getElementById('settingsStatus');
  if (!grid) return;
  if (status) status.innerHTML = '<span class="dot active"></span><span>Loading vault…</span>';
  apiFetch('/api/settings').then(function (r) { return r.json(); }).then(function (data) {
    SETTINGS_CACHE = data || null;
    renderToolGrid();
    var keys = (data && data.keys) || [];
    grid.innerHTML = keys.map(function (item) {
      return '<div class="settings-field' + (item.configured ? ' configured' : '') + '">' +
        '<div class="settings-meta"><label>' + escapeHtml(item.label) + '</label>' +
        '<span class="key-state">' + (item.configured ? '● set ' + escapeHtml(item.hint || '') : '○ not set') + '</span>' +
        '<span class="key-help">' + escapeHtml(item.help || '') + '</span></div>' +
        '<input type="password" data-key="' + escapeHtml(item.key) + '" placeholder="' +
        (item.configured ? '•••••• — enter new to replace' : 'paste key') + '" autocomplete="off" spellcheck="false" />' +
        '<div class="settings-row-actions">' +
        '<button type="button" class="btn btn-sm btn-primary" data-save-key="' + escapeHtml(item.key) + '">Save key</button>' +
        (item.configured ? '<button type="button" class="btn btn-sm btn-outline" data-clear-key="' + escapeHtml(item.key) + '">Clear</button>' : '') +
        '</div></div>';
    }).join('');
    var proxy = document.getElementById('settingsProxy');
    if (proxy && data) proxy.value = data.proxy || '';
    if (status) {
      status.innerHTML = '<span class="dot idle"></span><span>' +
        escapeHtml(String(data.configured || 0)) + ' of ' + escapeHtml(String(data.total || keys.length)) +
        ' keys configured — blank fields are left untouched</span>';
    }
    var k = document.getElementById('statKeys');
    if (k && data) k.textContent = (data.configured || 0) + '/' + (data.total || 0);
  }).catch(function () {
    if (status) status.innerHTML = '<span class="dot error"></span><span>Could not load vault.</span>';
  });
}

function postSettings(payload, btn, busyText) {
  var original = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = busyText || 'Saving…'; }
  return apiFetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
    .then(function (res) {
      if (btn) { btn.disabled = false; btn.textContent = original; }
      if (!res.ok) { showToast('Error: ' + (res.data.error || 'save failed'), 'error'); return res; }
      loadSettings();
      apiFetch('/api/status').then(function (r) { return r.json(); }).then(function (s) {
        updateProxyUI(s.proxy || '');
        updateEngineTags(s);
        updateOverview(s);
      }).catch(function () {});
      return res;
    }).catch(function (err) {
      if (btn) { btn.disabled = false; btn.textContent = original; }
      showToast('Error: ' + err.message, 'error');
      throw err;
    });
}

/* Per-row delegation: the grid is re-rendered on every load, so one
   listener on the container outlives the buttons inside it. */
function settingsGridClick(e) {
  var saveBtn = e.target.closest ? e.target.closest('[data-save-key]') : null;
  var clearBtn = e.target.closest ? e.target.closest('[data-clear-key]') : null;
  if (saveBtn) {
    var key = saveBtn.getAttribute('data-save-key');
    var grid = document.getElementById('settingsGrid');
    var input = grid ? grid.querySelector('input[data-key="' + key + '"]') : null;
    var val = input ? input.value.trim() : '';
    if (!val) { showToast('Paste a key first', 'error'); return; }
    var payload = {};
    payload[key] = val;
    postSettings(payload, saveBtn, 'Saving…').then(function (res) {
      if (res && res.ok) showToast('Key saved', 'success');
    });
    return;
  }
  if (clearBtn) {
    var ckey = clearBtn.getAttribute('data-clear-key');
    var cpayload = {};
    cpayload[ckey] = '';
    postSettings(cpayload, clearBtn, 'Clearing…').then(function (res) {
      if (res && res.ok) showToast('Key cleared', 'info');
    });
  }
}

function settingsGridKeydown(e) {
  if (e.key !== 'Enter') return;
  var input = e.target.closest ? e.target.closest('input[data-key]') : null;
  if (!input) return;
  e.preventDefault();
  var grid = document.getElementById('settingsGrid');
  var btn = grid ? grid.querySelector('[data-save-key="' + input.getAttribute('data-key') + '"]') : null;
  if (btn) btn.click();
}

function saveSettings() {
  var grid = document.getElementById('settingsGrid');
  var payload = {};
  if (grid) {
    grid.querySelectorAll('input[data-key]').forEach(function (el) {
      // Only send touched fields: blank = leave untouched (not clear).
      if (el.value && el.value.trim()) payload[el.getAttribute('data-key')] = el.value.trim();
    });
  }
  var proxy = document.getElementById('settingsProxy');
  if (proxy) payload.proxy = proxy.value.trim();
  if (!Object.keys(payload).length) { showToast('Nothing to save — paste a key first', 'error'); return; }
  var btn = document.getElementById('settingsSave');
  postSettings(payload, btn, 'Saving…').then(function (res) {
    if (res && res.ok) showToast('Settings saved (' + (res.data.configured || 0) + ' keys set)', 'success');
  }).catch(function () {});
}

/* Two stores, two timestamp dialects (spyglass seconds, lens
   microseconds+tz) — trim to whole seconds so runs read uniformly. */
function fmtRunAt(stamp) {
  return String(stamp || '').slice(0, 19);
}

/* One stored run as a table row.
 *
 * Legacy Lens-Extender runs live in their own store: they can be listed
 * and deleted, but the timeline/diff/dossier readers query the Spyglass
 * store only. Those rows are marked, so a click says the history is not
 * available instead of loading a target that answers "no stored runs"
 * for a row that is right there. */
function caseRowHtml(c) {
  var legacy = String(c.qtype || '').indexOf('lens_') === 0;
  var title = legacy
    ? 'Legacy Lens-Extender run — history is not available in this build'
    : 'Load this target\'s timeline';
  return '<tr class="case-row' + (legacy ? ' case-row-legacy' : '') +
         '" data-target="' + escapeHtml(c.target) +
         '" data-qtype="' + escapeHtml(c.qtype) +
         '"' + (legacy ? ' data-legacy="1"' : '') +
         ' title="' + escapeHtml(title) + '"><td>' + escapeHtml(c.target) +
         '</td><td>' + escapeHtml(c.qtype) + '</td><td>' + c.id + '</td><td>' +
         escapeHtml(fmtRunAt(c.run_at)) + '</td>' +
         '<td class="case-del-cell"><button type="button" class="case-del" data-del-id="' + c.id +
         '" data-del-qtype="' + escapeHtml(c.qtype) +
         '" title="Delete this stored run">✕</button></td></tr>';
}

function loadCases() {
  var container = document.getElementById('casesList');
  if (!container) return;
  apiFetch('/api/cases')
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (!data || data.length === 0) {
        container.innerHTML = '<p class="dim">No stored cases yet. Run a query with "Store in Cases" enabled.</p>';
        return;
      }
      var html = '<table><thead><tr><th>Target</th><th>Type</th><th>Run ID</th><th>Time</th><th></th></tr></thead><tbody>';
      data.forEach(function (c) { html += caseRowHtml(c); });
      html += '</tbody></table>';
      container.innerHTML = html;
    })
    .catch(function () {
      container.innerHTML = '<p class="dim">Could not load cases.</p>';
    });
}

/* ── Cases: diff / timeline / dossier ──
   Read-only queries against the store's entity index, so they answer
   inline instead of going through the scan job pool. */

function deleteCase(runId, qtype, btn) {
  if (!runId) return;
  var kind = qtype || 'unknown type';
  confirmAction({
    kicker: 'Delete stored run',
    title: 'Delete case #' + runId + '?',
    body: 'The ' + kind + ' run and its entities leave the index. This cannot be undone.',
    cancelLabel: 'Keep case',
    confirmLabel: 'Delete case'
  }).then(function (ok) {
    if (!ok) return;
    if (btn) btn.disabled = true;
    apiFetch('/api/cases/run?id=' + encodeURIComponent(runId) + '&qtype=' + encodeURIComponent(qtype || ''), {
      method: 'DELETE'
    }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
      .then(function (res) {
        if (!res.ok) {
          if (btn) btn.disabled = false;
          showToast('Error: ' + (res.data.error || 'delete failed'), 'error');
          return;
        }
        showToast('Case deleted — run #' + runId, 'success');
        loadCases();
      }).catch(function (err) {
        if (btn) btn.disabled = false;
        showToast('Error: ' + err.message, 'error');
      });
  });
}

function casesQuery(kind) {
  var target = (document.getElementById('casesTarget') || {}).value || '';
  var qtype = (document.getElementById('casesQtype') || {}).value || '';
  var out = document.getElementById('casesDetail');
  if (!out) return;
  target = target.trim();
  if (!target) {
    out.innerHTML = '<p class="dim">Enter a stored target first.</p>';
    return;
  }
  var url = '/api/cases/' + kind + '?target=' + encodeURIComponent(target);
  if (qtype) url += '&qtype=' + encodeURIComponent(qtype);
  out.innerHTML = '<p class="dim">Loading ' + kind + '…</p>';
  apiFetch(url)
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data && data.error) {
        out.innerHTML = '<p class="res-line">Error: <span class="status-err">' +
                        escapeHtml(data.error) + '</span></p>';
        return;
      }
      if (kind === 'diff') out.innerHTML = renderCaseDiff(data, qtype);
      else if (kind === 'timeline') out.innerHTML = renderCaseTimeline(data, qtype);
      else out.innerHTML = renderCaseProfile(data, qtype);
    })
    .catch(function (err) {
      out.innerHTML = '<p class="dim">Could not load ' + kind + '.</p>';
      showToast('Error: ' + err.message, 'error');
    });
}

/* "No results" has to say *why*. A stale Query Type filter looks exactly
   like a broken feature otherwise, so name the filter and offer the way
   out instead of a bare "no runs". */
function emptyCases(d, qtype, kind) {
  var target = (d && d.target) || '';
  var html = '<p class="dim">No ' + escapeHtml(kind === 'diff' ? 'comparable ' : '') +
             'stored runs match <strong>' + escapeHtml(target) + '</strong>' +
             (qtype ? ' with query type <strong>' + escapeHtml(qtype) + '</strong>' : '') +
             '.</p>';
  if (qtype) {
    html += '<p class="dim">The Query Type filter is narrowing this search. ' +
            '<a href="#" id="casesResetQtype">Search all query types</a>.</p>';
  }
  return html;
}

function entityList(title, items, cls) {
  if (!items || !items.length) {
    return '<p class="res-line">' + escapeHtml(title) + ': <span class="dim">none</span></p>';
  }
  var html = '<p class="res-line">' + escapeHtml(title) + ' (' + items.length + ')</p>';
  html += '<table class="res-table"><tbody>';
  items.forEach(function (item) {
    html += '<tr><td class="' + (cls || '') + '">' + escapeHtml(item) + '</td></tr>';
  });
  return html + '</tbody></table>';
}

function renderCaseDiff(d, qtype) {
  if (!d) return '<p class="dim">No data.</p>';
  var html = '<h3>Entity diff — ' + escapeHtml(d.target || '') +
             (d.qtype ? ' (' + escapeHtml(d.qtype) + ')' : '') + '</h3>';
  if (d.error) {
    if (!qtype && /need at least two/.test(d.error)) {
      return html + emptyCases(d, qtype, 'diff');
    }
    return html + '<p class="res-line">' + escapeHtml(d.error) + '</p>' +
           (qtype ? '<p class="dim">The Query Type filter is narrowing this search. ' +
                   '<a href="#" id="casesResetQtype">Search all query types</a>.</p>' : '');
  }
  html += '<p class="res-line">Comparing <span class="status-ok">' +
          escapeHtml(fmtRunAt(d.old_run || '?')) + '</span> → <span class="status-ok">' +
          escapeHtml(fmtRunAt(d.new_run || '?')) + '</span></p>';
  html += entityList('Added', d.added, 'status-ok');
  html += entityList('Removed', d.removed, 'status-err');
  return html;
}

function renderCaseTimeline(d, qtype) {
  var runs = (d && d.runs) || [];
  if (!runs.length) return emptyCases(d, qtype, 'timeline');
  var html = '<h3>Timeline — ' + escapeHtml(d.target || '') +
             ' (' + runs.length + ' run' + (runs.length === 1 ? '' : 's') + ')</h3>';
  html += '<table class="res-table"><thead><tr><th>Run</th><th>Type</th><th>Entities</th></tr></thead><tbody>';
  runs.slice().reverse().forEach(function (run) {
    var ents = run.entities || [];
    html += '<tr><td>' + escapeHtml(fmtRunAt(run.run_at)) + '</td><td>' + escapeHtml(run.qtype) +
            '</td><td>' + ents.length + '</td></tr>';
    /* Per-run entities inline: counts alone forced a second query to see
       what actually changed, which is what the diff view is for. Cap the
       chips so a 400-entity website run stays readable. */
    if (ents.length) {
      var shown = ents.slice(0, 12);
      html += '<tr class="case-ents-row"><td colspan="3"><div class="chip-group">';
      shown.forEach(function (e) {
        html += '<span class="chip">' + escapeHtml(e) + '</span>';
      });
      html += '</div>';
      if (ents.length > shown.length) {
        html += '<p class="dim">+ ' + (ents.length - shown.length) + ' more</p>';
      }
      html += '</td></tr>';
    }
  });
  html += '</tbody></table>';
  return html;
}

/* The last dossier payload, kept for the Copy / Download buttons below.
   Set on every profile render; never read when a profile failed. */
var lastDossier = null;

function renderCaseProfile(d, qtype) {
  if (!d) return '<p class="dim">No data.</p>';
  var results = d.results || {};
  if (!Object.keys(results).length && qtype) return emptyCases(d, qtype, 'profile');
  lastDossier = d;
  var html = '<h3>Dossier — ' + escapeHtml(d.target || '') + '</h3>';
  html += '<p class="res-line">Generated <span class="status-ok">' +
          escapeHtml(d.generated || '') + '</span> · schema v' +
          escapeHtml(String(d.schema_version === undefined ? '' : d.schema_version)) +
          ' · engine ' + escapeHtml(d.spyglass_version || '') + '</p>';
  var types = Object.keys(results);
  html += '<p class="res-line">Query types stored: <span class="status-ok">' +
          (types.length ? escapeHtml(types.join(', ')) : 'none') + '</span></p>';
  if (types.length) {
    html += '<div class="export-btns">' +
            '<button type="button" class="btn btn-sm btn-outline" id="dossierCopy">Copy dossier JSON</button>' +
            '<button type="button" class="btn btn-sm btn-outline" id="dossierDl">Download dossier</button></div>';
  }
  var entities = d.entities || {};
  Object.keys(entities).forEach(function (kind) {
    html += entityList(kind, entities[kind]);
  });
  if (!Object.keys(entities).length) {
    html += '<p class="dim">No entities extracted for this target.</p>';
  }
  return html;
}

function dossierFilename() {
  var t = (lastDossier && lastDossier.target) || 'dossier';
  var safe = String(t).toLowerCase().replace(/[^a-z0-9._+-]+/g, '_').slice(0, 60)
    .replace(/\.{2,}/g, '_').replace(/^[._-]+/, '');
  if (!safe) safe = 'dossier';
  return 'dossier-' + safe + '.json';
}

function copyDossier() {
  if (!lastDossier) return;
  var text = JSON.stringify(lastDossier, null, 2);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () {
      showToast('Dossier copied', 'success');
    }).catch(function (err) {
      showToast('Error: ' + err.message, 'error');
    });
  } else {
    showToast('Clipboard unavailable in this browser', 'error');
  }
}

function downloadDossier() {
  if (!lastDossier) return;
  var blob = new Blob([JSON.stringify(lastDossier, null, 2)], { type: 'application/json' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = dossierFilename();
  document.body.appendChild(a);
  a.click();
  setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 100);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ══════════════════════════════════════════════════════════════
   Targets + CHECK AGAIN — the tracked-target flow.

   Targets are managed entities (the TARGETS tab): added once, removed
   explicitly, rendered as rows. A social platform tab never configures
   a target — it resolves the one tracked for its platform and becomes
   its CHECK AGAIN dashboard: identity band, stat deltas, the diff, new
   posts, and the history rail.

   Honesty rule: every change claim on this screen comes from the
   server's diff engine (social/diff.py) via the target detail's
   ``last_diff`` — re-derived with the same engine the check used. This
   file only renders it. A second, client-side diff implementation is
   how the UI starts claiming things the engine would refuse.
   ══════════════════════════════════════════════════════════════ */

var TARGETS_CACHE = [];            // last GET /api/social/targets
var dashboardTarget = null;        // target the social panel is showing
var pendingDashboardTarget = null; // explicit pick from a Targets row
var dashboardHasTarget = false;     // a target resolved on the visible tab
var dashboardHistory = [];         // newest-first snapshots for this tab
var dashboardIndex = 0;            // snapshot the main column is showing
var dashboardDetail = null;        // last target-detail response

var WHEN_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/* "28 Oct · 08:29" — one date dialect for the whole flow. */
function fmtWhen(stamp) {
  if (!stamp) return '';
  var d = new Date(stamp);
  if (isNaN(d.getTime())) return String(stamp).slice(0, 19);
  var hh = d.getHours() < 10 ? '0' + d.getHours() : '' + d.getHours();
  var mm = d.getMinutes() < 10 ? '0' + d.getMinutes() : '' + d.getMinutes();
  return d.getDate() + ' ' + WHEN_MONTHS[d.getMonth()] + ' · ' + hh + ':' + mm;
}

function findTargetById(id) {
  for (var i = 0; i < TARGETS_CACHE.length; i++) {
    if (TARGETS_CACHE[i].id === id) return TARGETS_CACHE[i];
  }
  return null;
}

function socialFieldLabel(key) {
  if (typeof SOCIAL_FIELDS !== 'undefined' && SOCIAL_FIELDS) {
    for (var i = 0; i < SOCIAL_FIELDS.length; i++) {
      if (SOCIAL_FIELDS[i].key === key) return SOCIAL_FIELDS[i].label;
    }
  }
  return key;
}

function socialFieldType(key) {
  if (typeof SOCIAL_FIELDS !== 'undefined' && SOCIAL_FIELDS) {
    for (var i = 0; i < SOCIAL_FIELDS.length; i++) {
      if (SOCIAL_FIELDS[i].key === key) return SOCIAL_FIELDS[i].type;
    }
  }
  return null;
}

/* ── The burner account lives in Settings (account config, not target
   config), kept in this browser and attached to a check payload only
   for platforms whose registry entry declares a login. ── */
function loadBurnerConfig() {
  try {
    var raw = localStorage.getItem('spyglass_burner');
    return raw ? JSON.parse(raw) : null;
  } catch (e) { return null; }
}

function loadBurnerSettings() {
  var enabled = document.getElementById('settingsBurnerEnabled');
  var user = document.getElementById('settingsBurnerUser');
  var pass = document.getElementById('settingsBurnerPass');
  if (!enabled && !user && !pass) return;
  var cfg = loadBurnerConfig() || {};
  if (enabled) enabled.checked = !!cfg.enabled;
  if (user) user.value = cfg.username || '';
  if (pass) pass.value = cfg.password || '';
}

function saveBurnerSettings() {
  var enabled = document.getElementById('settingsBurnerEnabled');
  var user = document.getElementById('settingsBurnerUser');
  var pass = document.getElementById('settingsBurnerPass');
  var cfg = {
    enabled: !!(enabled && enabled.checked),
    username: user ? user.value.trim() : '',
    password: pass ? pass.value : ''
  };
  var empty = !cfg.enabled && !cfg.username && !cfg.password;
  try {
    if (empty) localStorage.removeItem('spyglass_burner');
    else localStorage.setItem('spyglass_burner', JSON.stringify(cfg));
  } catch (e) {
    showToast('Browser storage unavailable — the burner login cannot be kept here.', 'error');
    return;
  }
  if (empty) { showToast('Burner login cleared', 'info'); return; }
  if (cfg.enabled && !cfg.username) {
    showToast('Burner enabled — enter the username before running a check.', 'error');
    return;
  }
  showToast('Burner login saved in this browser', 'success');
}

/* ── Targets tab ── */

function targetRowHtml(t) {
  var cfg = loadBurnerConfig();
  var meta = (typeof SOCIAL_META !== 'undefined') && SOCIAL_META ? SOCIAL_META[t.platform] : null;
  var burner = !!(cfg && cfg.enabled && cfg.username && meta &&
                  meta.login && meta.login !== 'none');
  var baseline = t.baseline_at ? 'baseline ' + fmtWhen(t.baseline_at) : 'no checks yet';
  var right = t.checks
    ? pluralize(t.checks, 'check') +
      (t.last_check_at ? ' · last ' + fmtWhen(t.last_check_at) : '')
    : 'not checked yet';
  var failed = !!(t.last_status && t.last_status !== 'ok' && t.last_status !== 'partial');
  return '<div class="trow">' +
    '<div class="t-n"><b>' + escapeHtml(t.handle) +
      (burner ? ' <span class="pill">BURNER</span>' : '') + '</b>' +
      '<span>' + escapeHtml(socialLabel(t.platform)) + ' · ' + escapeHtml(baseline) +
      (failed ? ' · <span class="status-err">last check failed</span>' : '') + '</span></div>' +
    '<span class="t-r">' + escapeHtml(right) + '</span>' +
    '<span class="t-act">' +
      '<button type="button" class="btn btn-sm btn-primary" data-check-id="' +
        t.id + '">CHECK NOW</button>' +
      '<button type="button" class="t-del" data-del-id="' + t.id + '">remove</button>' +
    '</span></div>';
}

function loadTargets() {
  var list = document.getElementById('targetsList');
  return apiFetch('/api/social/targets')
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data && data.error) throw new Error(String(data.error));
      TARGETS_CACHE = Array.isArray(data) ? data : [];
      var count = document.getElementById('targetsCount');
      if (count) count.textContent = 'Tracked (' + TARGETS_CACHE.length + ')';
      var stat = document.getElementById('statTargets');
      if (stat) stat.textContent = TARGETS_CACHE.length;
      if (!list) return;
      if (!TARGETS_CACHE.length) {
        list.innerHTML = '<p class="targets-empty">No targets yet. Add a platform and handle above — ' +
          'that platform\'s tab then becomes its CHECK AGAIN dashboard.</p>';
        return;
      }
      list.innerHTML = TARGETS_CACHE.map(targetRowHtml).join('');
    })
    .catch(function () {
      if (list) {
        list.innerHTML = '<p class="targets-empty">Could not load the target store — ' +
          'is the server running? Reload to try again.</p>';
      }
    });
}

function addTargetFromForm() {
  var sel = document.getElementById('targetPlatform');
  var input = document.getElementById('targetHandle');
  var btn = document.getElementById('targetAddBtn');
  var platform = sel ? sel.value : '';
  var handle = input ? input.value.trim() : '';
  if (!platform) { showToast('Pick a platform first', 'error'); return; }
  if (!handle) { showToast('Enter a handle', 'error'); return; }
  if (btn) { btn.disabled = true; btn.textContent = 'Adding…'; }
  apiFetch('/api/social/targets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ platform: platform, handle: handle })
  }).then(function (r) {
    return r.json().then(function (d) { return { ok: r.ok, data: d }; });
  }).then(function (res) {
    if (btn) { btn.disabled = false; btn.textContent = 'Add Target'; }
    if (!res.ok) {
      showToast('Error: ' + ((res.data && res.data.error) || 'could not add target'), 'error');
      return;
    }
    showToast('Now tracking @' + ((res.data && res.data.handle) || handle) +
              ' on ' + socialLabel(platform), 'success');
    if (input) input.value = '';
    loadTargets();
  }).catch(function (err) {
    if (btn) { btn.disabled = false; btn.textContent = 'Add Target'; }
    showToast('Error: ' + ((err && err.message) || err), 'error');
  });
}

function removeTargetFlow(id, btn) {
  var t = findTargetById(id);
  confirmAction({
    kicker: 'Forget target',
    title: 'Remove @' + (t ? t.handle : '#' + id) + '?',
    body: 'Its baseline, snapshots and check history are deleted from the store. ' +
          'This cannot be undone.',
    cancelLabel: 'Keep tracking',
    confirmLabel: 'Remove target'
  }).then(function (ok) {
    if (!ok) return;
    if (btn) btn.disabled = true;
    apiFetch('/api/social/targets/' + id, { method: 'DELETE' })
      .then(function (r) {
        return r.json().then(function (d) { return { ok: r.ok, data: d }; });
      })
      .then(function (res) {
        if (!res.ok) {
          if (btn) btn.disabled = false;
          showToast('Error: ' + ((res.data && res.data.error) || 'remove failed'), 'error');
          return;
        }
        showToast('Removed @' + (t ? t.handle : '#' + id), 'success');
        loadTargets();
        if (dashboardTarget && dashboardTarget.id === id) {
          loadSocialDashboard(dashboardTarget.platform);
        }
      })
      .catch(function (err) {
        if (btn) btn.disabled = false;
        showToast('Error: ' + ((err && err.message) || err), 'error');
      });
  });
}

/* Social scan summary removed: its title duplicated the identity band,
   its counts duplicated the stat cards and its baseline duplicated the
   status line. The centered capability line (#socialCaps) is the one
   honest "what this platform returns" note now. */
function gotoTab(panelId, platform) {
  var item = document.querySelector('.nav-item[data-panel="' + panelId + '"]' +
    (platform ? '[data-platform="' + platform + '"]' : ''));
  if (item && item.click) { item.click(); return true; }
  return false;
}

function openTargetsPanel() {
  if (!gotoTab('targets')) openPanelDirectly('targets');
}

function openTargetDashboard(id) {
  var t = findTargetById(id);
  if (!t) {
    showToast('That target is no longer tracked — the list will refresh.', 'error');
    loadTargets();
    return;
  }
  pendingDashboardTarget = id;
  /* Ride the existing nav wiring: the click activates the panel AND
     selects the platform, which resolves this dashboard. */
  if (!gotoTab('social', t.platform)) {
    openPanelDirectly('social');
    selectSocialPlatform(t.platform);
  }
  checkTarget(t);
}

/* ── The CHECK AGAIN dashboard ── */

function resolveDashboardTarget(key, explicitId) {
  if (explicitId) {
    var picked = findTargetById(explicitId);
    if (picked && picked.platform === key) return picked;
  }
  for (var i = 0; i < TARGETS_CACHE.length; i++) {
    if (TARGETS_CACHE[i].platform === key) return TARGETS_CACHE[i];
  }
  return null;
}

function loadSocialDashboard(key, explicitId) {
  var wantId = explicitId || pendingDashboardTarget;
  pendingDashboardTarget = null;
  return apiFetch('/api/social/targets')
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data && data.error) throw new Error(String(data.error));
      TARGETS_CACHE = Array.isArray(data) ? data : [];
      var target = resolveDashboardTarget(key, wantId);
      dashboardTarget = target || null;
      if (!target) {
        paintDashboardHead(key, null, null);
        paintDashboardBlank('No target on this tab yet',
          'Add <b>' + escapeHtml(key) + '</b> once on the ' +
          '<button type="button" class="btn btn-sm btn-outline" id="gotoTargets">Targets</button> ' +
          'tab — this tab then tracks it.');
        return;
      }
      return apiFetch('/api/social/targets/' + target.id + '?limit=20')
        .then(function (r) { return r.json(); })
        .then(function (detail) {
          if (detail && detail.error) throw new Error(String(detail.error));
          paintDashboard(key, target, detail || {});
        });
    })
    .catch(function (err) {
      dashboardTarget = null;
      paintDashboardHead(key, null, null);
      paintDashboardBlank('Could not load the dashboard',
        escapeHtml(String((err && err.message) || err)) +
        ' — check the server, then reload. Nothing on this screen is guessed ' +
        'while the store is unreachable.');
    });
}

function paintDashboardHead(key, target, detail) {
  var name = document.getElementById('socialPlatformName');
  if (name) name.textContent = socialLabel(key);
  var subject = document.getElementById('socialHandleTitle');
  if (subject) subject.textContent = target ? target.handle : 'no target';
  var btn = document.getElementById('socialCheckBtn');
  if (btn) btn.disabled = !target;
  var pill = document.getElementById('socialBurnerPill');
  var loggedIn = !!(detail && Array.isArray(detail.history) && detail.history[0] &&
                    detail.history[0].payload && detail.history[0].payload.logged_in);
  if (pill) pill.hidden = !loggedIn;
  var when = document.getElementById('socialWhen');
  if (!when) return;
  if (!target) {
    when.hidden = true;
    return;
  }
  /* ONE honest status line. Before a baseline exists, "last check <time>"
     beside "0 checks" read as a contradiction — the only thing worth
     saying then is that there is no baseline, plus why if the attempt
     failed. Red is never spent on the baseline: it belongs to change
     and severity. */
  var failed = !!(target.last_status && target.last_status !== 'ok' &&
                  target.last_status !== 'partial');
  var parts = [];
  if (target.checks) {
    if (target.last_check_at) {
      parts.push('◷ last check <b>' + escapeHtml(fmtWhen(target.last_check_at)) + '</b>');
    }
    if (target.baseline_at) {
      parts.push('baseline <b>' + escapeHtml(fmtWhen(target.baseline_at)) + '</b>');
    }
  } else {
    parts.push('no baseline yet');
    if (failed && target.last_status) {
      parts.push('<span class="status-err">last attempt failed: ' +
        escapeHtml(String(target.last_status).slice(0, 140)) + '</span>');
    }
  }
  when.hidden = false;
  when.innerHTML = parts.join(' · ');
}

function blankStateHtml(title, bodyHtml) {
  return '<div class="blank-state"><div class="bs-t">' + escapeHtml(title) +
         '</div>' + bodyHtml + '</div>';
}

function paintDashboardBlank(title, bodyHtml) {
  dashboardHasTarget = false;
  dashboardHistory = [];
  dashboardIndex = 0;
  dashboardDetail = null;
  var stats = document.getElementById('socialStats');
  var diff = document.getElementById('socialDiff');
  var media = document.getElementById('socialMedia');
  var posts = document.getElementById('socialPosts');
  var rail = document.getElementById('socialHistory');
  if (stats) { stats.innerHTML = ''; stats.hidden = true; }
  if (media) media.innerHTML = '';
  if (posts) posts.innerHTML = '';
  if (rail) rail.innerHTML = '';
  if (diff) diff.innerHTML = blankStateHtml(title, bodyHtml);
  refreshScanMode();
}

function paintDashboard(key, target, detail) {
  paintDashboardHead(key, target, detail);
  dashboardHasTarget = true;
  dashboardDetail = detail || {};
  dashboardHistory = Array.isArray(detail.history) ? detail.history : [];
  dashboardIndex = 0;  // every load opens on the newest check
  paintDashboardSelection(key, target, detail);
}

/* The main column follows dashboardIndex. Selecting a past card in the
   rail only repaints these panes — no refetch, and no client-side diff:
   each entry carries the verdict the server's diff engine computed. */
function paintDashboardSelection(key, target, detail) {
  var history = dashboardHistory;
  var index = Math.max(0, Math.min(dashboardIndex,
                                   Math.max(0, history.length - 1)));
  dashboardIndex = index;
  var entry = history[index] || null;
  var verdict;
  if (entry && entry.diff) {
    verdict = entry.diff;
  } else if (index === 0) {
    verdict = (detail && detail.last_diff) || null;
  } else {
    verdict = { ok: false, changed: false,
                error: 'no comparison was stored for this check' };
  }
  var stats = document.getElementById('socialStats');
  var diff = document.getElementById('socialDiff');
  var media = document.getElementById('socialMedia');
  var posts = document.getElementById('socialPosts');
  var rail = document.getElementById('socialHistory');
  if (stats) {
    stats.innerHTML = statCardsHtml(target, history, verdict, index);
    stats.hidden = !stats.innerHTML;  // no lone "CHECKS 0" box
  }
  if (diff) diff.innerHTML = dashDiffHtml(verdict, target, history, index);
  if (media) media.innerHTML = mediaPanelHtml(target, entry, key);
  if (posts) posts.innerHTML = newPostsHtml(verdict, target);
  if (rail) rail.innerHTML = historyRailHtml(target, history, index);
  refreshScanMode();
}

/* Which stats have a panel behind them — the same predicate the diff
   renderer uses, so a chevron never points at nothing. */
function dashToggles(verdict) {
  var set = {};
  if (!verdict || !verdict.ok) return set;
  Object.keys(verdict.lists || {}).forEach(function (kind) {
    var e = verdict.lists[kind] || {};
    if (e.refused || e.added_refused || e.removed_refused ||
        (e.added && e.added.length) || (e.removed && e.removed.length)) {
      set[kind] = true;
    }
  });
  if (verdict.posts && verdict.posts.added_count) set.posts = true;
  if (verdict.fields && verdict.fields.length) set.fields = true;
  return set;
}

var COUNT_SPECS = ['follower_count', 'following_count', 'post_count'];

/* Count key → the diff engine's list kind (singular → plural). */
var COUNT_TOGGLES = {
  follower_count: 'followers',
  following_count: 'following',
  post_count: 'posts'
};

function statCardsHtml(target, history, verdict, index) {
  /* No checks yet → no stat row at all. A lone "CHECKS 0 / no baseline"
     card above a blank state that says the same thing twice was the
     loudest noise on the unchecked dashboard. */
  if (!history || !history.length) return '';
  var at = Math.max(0, Math.min(index || 0, history.length - 1));
  var latest = history[at] ? history[at].payload : null;
  var prev = history[at + 1] ? history[at + 1].payload : null;
  var toggles = dashToggles(verdict);
  var versus = at === 0 ? 'vs last check' : 'vs previous check';
  var html = '';
  COUNT_SPECS.forEach(function (key) {
    var value = latest ? latest[key] : null;
    /* Unread is not zero: a count the platform did not report never
       renders a number, delta or placeholder here. */
    if (typeof value !== 'number') return;
    var delta = (prev && typeof prev[key] === 'number') ? value - prev[key] : null;
    var deltaHtml;
    if (delta === null) {
      deltaHtml = '<span class="stat-delta">first check · no delta yet</span>';
    } else if (delta > 0) {
      deltaHtml = '<span class="stat-delta up">▲ +' + delta + ' ' + versus + '</span>';
    } else if (delta < 0) {
      deltaHtml = '<span class="stat-delta">▼ ' + delta + ' ' + versus + '</span>';
    } else {
      deltaHtml = '<span class="stat-delta">· no change ' + versus + '</span>';
    }
    var toggleKey = COUNT_TOGGLES[key];
    var canToggle = !!toggles[toggleKey];
    html += '<div class="stat-card' + (canToggle ? ' click' : '') + '"' +
      (canToggle ? ' data-toggle="' + toggleKey + '"' : '') + '>' +
      '<span class="stat-label">' + escapeHtml(socialFieldLabel(key)) +
      (canToggle ? '<span class="chev">▾</span>' : '') + '</span>' +
      '<span class="stat-num">' + value.toLocaleString() + '</span>' +
      deltaHtml + '</div>';
  });
  html += '<div class="stat-card"><span class="stat-label">Checks</span>' +
    '<span class="stat-num">' + (target.checks || 0) + '</span>' +
    '<span class="stat-delta">' +
    (target.baseline_at ? 'baseline ' + escapeHtml(fmtWhen(target.baseline_at))
                        : 'no baseline yet') +
    (at > 0 ? ' · showing ' + escapeHtml(fmtWhen(history[at].taken_at)) : '') +
    '</span></div>';
  return html;
}

function listVerb(kind, isAdd) {
  if (kind === 'followers') return isAdd ? 'new follower' : 'unfollowed';
  if (kind === 'following') return isAdd ? 'now following' : 'no longer following';
  return isAdd ? 'added' : 'removed';
}

function diffRowHtml(name, tag, isNew) {
  var initials = String(name).replace(/[^a-z0-9]/gi, '').slice(0, 2).toUpperCase() || '??';
  return '<div class="drow"><span class="dav' + (isNew ? '' : ' out') + '">' +
    escapeHtml(initials) + '</span><span class="dname">' + escapeHtml(name) +
    '</span><span class="dtag' + (isNew ? ' red' : '') + '">' +
    escapeHtml(tag) + '</span></div>';
}

function listPanelHtml(kind, entry, latestPayload, since) {
  if (!entry) return '';
  var added = entry.added || [];
  var removed = entry.removed || [];
  var hasChange = !!(added.length || removed.length);
  var hasRefusal = !!(entry.refused || entry.added_refused || entry.removed_refused);
  if (!hasChange && !hasRefusal) return '';

  var title = kind.charAt(0).toUpperCase() + kind.slice(1);
  var head;
  if (hasChange) {
    var bits = [];
    if (added.length) bits.push('+' + added.length + ' new');
    if (removed.length) bits.push('−' + removed.length + ' ' + listVerb(kind, false));
    head = bits.join(', ') + (since ? ' since ' + since : '');
  } else {
    head = 'no diff claimed';
  }

  var html = '<div class="diff-panel" data-list="' + escapeHtml(kind) + '"><h3>' +
    escapeHtml(title) + ' · ' + escapeHtml(head) + '</h3>';
  if (entry.refused) {
    html += '<div class="dnote">' + escapeHtml(entry.refused) + '</div>';
  } else {
    if (entry.added_refused) {
      html += '<div class="dnote">' + escapeHtml(entry.added_refused) + '</div>';
    }
    if (entry.removed_refused) {
      html += '<div class="dnote">' + escapeHtml(entry.removed_refused) + '</div>';
    }
    if (hasChange) {
      html += '<div class="drows">';
      added.slice(0, 60).forEach(function (h) {
        html += diffRowHtml(h, listVerb(kind, true), true);
      });
      removed.slice(0, 60).forEach(function (h) {
        html += diffRowHtml(h, listVerb(kind, false), false);
      });
      html += '</div>';
    }
  }
  /* Completeness frame on every claim: what the collector actually saw. */
  var list = (latestPayload && latestPayload.lists && latestPayload.lists[kind]) || null;
  var foot = [];
  if (hasChange) foot.push(pluralize(added.length + removed.length, 'change'));
  if (list && list.complete === false) {
    var seen = list.limit || list.expected ||
      (Array.isArray(list.handles) ? list.handles.length : null);
    foot.push('sampled first ' + (seen || '?') +
      ' — changes below are real, but absence of change here does not prove the list held');
  }
  if (foot.length) html += '<div class="dfoot">' + escapeHtml(foot.join(' · ')) + '</div>';
  return html + '</div>';
}

function shortVal(v) {
  if (v === null || v === undefined || v === '') return '—';
  var s = Array.isArray(v) ? v.join(', ') : String(v);
  return s.length > 160 ? s.slice(0, 157) + '…' : s;
}

/* A URL change has to be verifiable by clicking — a truncated display
   string ending in "…" is not a URL, and pasting it gets rejected.
   Link-type field values render the full href behind a short
   host + path label. */
function linkValHtml(v) {
  var s = (v === null || v === undefined) ? '' : String(v);
  if (!/^https?:\/\//i.test(s)) return escapeHtml(shortVal(s));
  var label = s;
  try {
    var u = new URL(s);
    label = u.hostname.replace(/^www\./, '') + (u.pathname === '/' ? '' : u.pathname);
    if (u.search) label += '?…';
  } catch (e) { /* not parseable — fall through to the shortened raw value */ }
  if (label.length > 72) label = label.slice(0, 69) + '…';
  return '<a href="' + escapeHtml(s) + '" target="_blank" rel="noopener noreferrer">' +
    escapeHtml(label) + '</a>';
}

function dashDiffHtml(verdict, target, history, index) {
  if (!verdict) {
    return blankStateHtml('No baseline yet',
      'The first successful check records it; every later check is described against it.');
  }
  var at = Math.max(0, Math.min(index || 0,
                                Math.max(0, (history || []).length - 1)));
  /* The oldest retained check is the baseline — including when retention
     pruned the original first check. A state, not an engine refusal. */
  if (history && history.length && at === history.length - 1) {
    return blankStateHtml('Baseline recorded',
      'The next check is described against it.');
  }
  if (!verdict.ok) {
    /* Baseline wording and refusals come straight from the engine —
       "could not compare" must never render as "nothing changed". */
    return '<div class="diff-none">' +
      escapeHtml(verdict.error || 'could not compare these checks') + '</div>';
  }
  var latest = history[at] ? history[at].payload : {};
  var since = history[at + 1] ? fmtWhen(history[at + 1].taken_at)
    : (target && target.baseline_at ? fmtWhen(target.baseline_at) : 'the baseline');
  var html = '';
  Object.keys(verdict.lists || {}).forEach(function (kind) {
    html += listPanelHtml(kind, verdict.lists[kind], latest, since);
  });
  if (verdict.fields && verdict.fields.length) {
    html += '<div class="diff-panel" data-list="fields"><h3>Profile fields · ' +
      pluralize(verdict.fields.length, 'change') + '</h3>';
    verdict.fields.slice(0, 30).forEach(function (f) {
      var type = socialFieldType(f.key);
      var note = (type === 'link' || type === 'image')
        ? (linkValHtml(f.old) + '<span class="darrow">→</span>' + linkValHtml(f.new))
        : (escapeHtml(shortVal(f.old)) + ' → ' + escapeHtml(shortVal(f.new)));
      html += '<div class="drow"><span class="dname">' +
        escapeHtml(f.label || f.key) + '</span>' +
        '<span class="dtag red">changed</span></div>' +
        '<div class="dnote">' + note + '</div>';
    });
    html += '</div>';
  }
  var walls = verdict.walls || {};
  var walled = walls.new || [];
  var resolved = walls.resolved || [];
  if (walled.length || resolved.length) {
    html += '<div class="diff-panel" data-list="walls"><h3>List access changed</h3>';
    walled.forEach(function (w) {
      html += '<div class="drow"><span class="dname">' +
        escapeHtml(w.label || w.kind || 'list') + '</span>' +
        '<span class="dtag red">now walled</span></div>' +
        '<div class="dnote">' + escapeHtml(w.why || 'refused this check') + '</div>';
    });
    resolved.forEach(function (kind) {
      html += '<div class="drow"><span class="dname">' + escapeHtml(kind) +
        '</span><span class="dtag">accessible again</span></div>';
    });
    html += '</div>';
  }
  /* A refused phase renders its reason — "could not compare" must never
     look like "nothing changed", even when everything else held. */
  if (verdict.posts && verdict.posts.refused) {
    html += '<div class="diff-none">' + escapeHtml(verdict.posts.refused) + '</div>';
  }
  if (html) return html;
  var moved = (verdict.counts || []).some(function (c) { return c.delta; });
  if (moved) {
    return '<div class="diff-none">Count changes only — see the stat deltas above. ' +
      'No list, profile or wall changes to report.</div>';
  }
  return '<div class="diff-none">No changes since the previous check — ' +
    'counts held and the lists matched.</div>';
}

function newPostsHtml(verdict, target) {
  var added = (verdict && verdict.ok && verdict.posts && verdict.posts.added) || [];
  if (!added.length) return '';
  var handle = (target && target.handle) || '';
  var initial = (handle.charAt(0) || '?').toUpperCase();
  var html = '<div class="nposts"><h2>New posts (' + added.length + ')</h2>';
  added.slice(0, 20).forEach(function (post) {
    var meta = '<b>' + escapeHtml(handle) + '</b>';
    if (post.timestamp) {
      meta += '<span>' + escapeHtml(String(post.timestamp).slice(0, 10)) + '</span>';
    }
    var href = safeHref(post.url || '');
    if (href) {
      meta += '<a href="' + escapeHtml(href) + '" target="_blank" rel="noopener">open ↗</a>';
    }
    html += '<div class="npost"><div class="np-av">' + escapeHtml(initial) +
      '</div><div><div class="np-meta">' + meta + '</div>' +
      '<div class="np-txt">' + escapeHtml(post.caption || '(no caption)') +
      '</div></div></div>';
  });
  if (added.length > 20) {
    html += '<p class="dim">+ ' + (added.length - 20) + ' more in the run log</p>';
  }
  return html + '</div>';
}

function countLine(payload) {
  var parts = [];
  COUNT_SPECS.forEach(function (key) {
    var v = payload ? payload[key] : null;
    if (typeof v === 'number') {
      parts.push(v.toLocaleString() + ' ' + socialFieldLabel(key).toLowerCase());
    }
  });
  return parts.length ? parts.join(' · ') : 'profile recorded';
}

function countDeltas(oldPayload, newPayload) {
  var parts = [];
  COUNT_SPECS.forEach(function (key) {
    var before = oldPayload ? oldPayload[key] : null;
    var after = newPayload ? newPayload[key] : null;
    if (typeof before !== 'number' || typeof after !== 'number') return;
    var delta = after - before;
    if (!delta) return;
    var label = socialFieldLabel(key).toLowerCase();
    if (delta > 0) parts.push('<span class="chg">+' + delta + ' ' + label + '</span>');
    else parts.push('−' + Math.abs(delta) + ' ' + label);
  });
  return parts;
}

function fmtUnix(ts) {
  if (typeof ts !== 'number' || !isFinite(ts)) return '';
  var d = new Date(ts * 1000);
  if (isNaN(d.getTime())) return '';
  return fmtWhen(d.toISOString());
}

function historyRailHtml(target, history, selectedIndex) {
  if (!history || !history.length) return '';
  var at = Math.max(0, Math.min(selectedIndex || 0, history.length - 1));
  /* Newest first: the card the dashboard opens on is at the top. */
  var html = '<div class="hist-sect"><h2>History <span class="hist-sub">' +
    'newest first</span></h2><div class="tl-list">';
  history.forEach(function (entry, i) {
    var payload = entry.payload || {};
    var body;
    if (i === history.length - 1) {
      body = '<b>Baseline established</b><br>' + escapeHtml(countLine(payload));
    } else {
      var parts = countDeltas(history[i + 1].payload, payload);
      body = parts.length ? parts.join(' · ')
        : '<span class="same">no changes · counts held</span>';
    }
    if (payload.status === 'partial') {
      body += '<br><span class="same">partial lists this check</span>';
    }
    html += '<button type="button" class="tl-row' + (i === at ? ' active' : '') +
      '" data-hist-index="' + i + '"' +
      (i === at ? ' aria-current="true"' : '') + '>' +
      '<span class="tl-dot" aria-hidden="true"></span>' +
      '<span class="tl-main"><span class="tl-time">' +
      escapeHtml(fmtWhen(entry.taken_at)) +
      (i === 0 ? '<span class="tl-tag">latest</span>' : '') +
      '</span><span class="tl-body">' + body + '</span></span></button>';
  });
  return html + '</div></div>';
}

/* ── Media for one check ──
 *
 * Stories and post files are captured per snapshot, so a timeline card is
 * also a media date. Three states stay distinct on purpose: undefined
 * (snapshot predates capture), null (capture attempted and unavailable),
 * and an empty list (captured; there was nothing).
 */
function mediaNoteHtml(text) {
  return '<p class="media-note">' + escapeHtml(text) + '</p>';
}

function mediaIsVideo(path) {
  return /\.(mp4|webm|mov|m4v)$/i.test(String(path || ''));
}

function mediaUrl(target, path) {
  return '/api/social/media/' + target.id + '?path=' + encodeURIComponent(path);
}

function mediaTileHtml(target, path, label) {
  var video = mediaIsVideo(path);
  var src = mediaUrl(target, path);
  var inner = video
    ? '<span class="mt-play" aria-hidden="true">▶</span><span class="mt-kind">video</span>'
    : '<img src="' + escapeHtml(src) + '" alt="" loading="lazy" />';
  return '<button type="button" class="mtile' + (video ? ' video' : '') + '"' +
    ' data-media-src="' + escapeHtml(src) + '"' +
    ' data-media-kind="' + (video ? 'video' : 'image') + '"' +
    ' data-media-caption="' + escapeHtml(label) + '"' +
    ' title="' + escapeHtml(label) + '">' + inner + '</button>';
}

function mediaPanelHtml(target, entry, platformKey) {
  if (!target || !entry) return '';
  var payload = entry.payload || {};
  var caps = Array.isArray(payload.capabilities) ? payload.capabilities : [];
  var capable = platformKey === 'instagram' ||
    caps.indexOf('media') >= 0 || caps.indexOf('stories') >= 0;
  if (!capable) return '';

  var stories = payload.stories;
  var storyItems = (stories && Array.isArray(stories.items)) ? stories.items : [];
  var storyFiles = storyItems.filter(function (s) { return s && s.file; });
  var posts = Array.isArray(payload.posts) ? payload.posts : [];
  var postTiles = [];
  var postsHaveMediaKey = false;
  posts.forEach(function (post) {
    if (!post || typeof post !== 'object') return;
    if (Object.prototype.hasOwnProperty.call(post, 'media_files')) {
      postsHaveMediaKey = true;
    }
    (post.media_files || []).forEach(function (path) {
      if (typeof path !== 'string' || !path) return;
      var label = post.caption ? String(post.caption) : 'Post';
      if (post.timestamp) label = (fmtUnix(post.timestamp) || '') + ' · ' + label;
      postTiles.push({ path: path, label: label });
    });
  });

  var html = '<div class="media-sect"><div class="media-head"><h2>Media</h2>' +
    '<span class="media-when">' + escapeHtml(fmtWhen(entry.taken_at)) +
    '</span></div>';

  html += '<div class="media-group"><h3>Stories</h3>';
  if (stories === undefined) {
    html += mediaNoteHtml('Stories were not captured in this check — '
      + 'this snapshot predates story capture.');
  } else if (stories === null) {
    html += mediaNoteHtml('Stories were not captured — they need a burner '
      + 'login and an active story tray.');
  } else if (!storyFiles.length) {
    html += mediaNoteHtml(storyItems.length
      ? storyItems.length + ' story item(s) seen, none downloaded — '
        + 'enable Download Media before checking.'
      : 'No active stories in this check’s 24-hour window.');
  } else {
    html += '<div class="media-grid">';
    storyFiles.slice(0, 60).forEach(function (s) {
      html += mediaTileHtml(target, s.file,
        'Story · ' + (fmtUnix(s.taken_at) || 'time unknown'));
    });
    html += '</div>';
    if (storyFiles.length > 60) {
      html += mediaNoteHtml('+ ' + (storyFiles.length - 60) +
        ' more story items in this check.');
    }
  }
  html += '</div>';

  html += '<div class="media-group"><h3>Posts</h3>';
  if (postTiles.length) {
    html += '<div class="media-grid">';
    postTiles.slice(0, 60).forEach(function (tile) {
      html += mediaTileHtml(target, tile.path, tile.label);
    });
    html += '</div>';
    if (postTiles.length > 60) {
      html += mediaNoteHtml('+ ' + (postTiles.length - 60) +
        ' more files in this check.');
    }
  } else if (!posts.length) {
    html += mediaNoteHtml('No posts were retrieved in this check.');
  } else if (!postsHaveMediaKey) {
    html += mediaNoteHtml('Post media was not linked to posts in this snapshot '
      + '— it predates per-post media capture.');
  } else {
    html += mediaNoteHtml('No post media was downloaded for this check — '
      + 'enable Download Media and check again.');
  }
  return html + '</div></div>';
}

function openMediaLightbox(src, kind, caption) {
  var box = document.getElementById('mediaLightbox');
  var stage = document.getElementById('mediaLightboxStage');
  var cap = document.getElementById('mediaLightboxCaption');
  if (!box || !stage) return;
  stage.innerHTML = '';
  var node;
  if (kind === 'video') {
    node = document.createElement('video');
    node.src = src;
    node.controls = true;
    node.autoplay = true;
    node.playsInline = true;
  } else {
    node = document.createElement('img');
    node.src = src;
    node.alt = caption || '';
  }
  stage.appendChild(node);
  if (cap) {
    cap.textContent = caption || '';
    cap.hidden = !caption;
  }
  box.hidden = false;
}

function closeMediaLightbox() {
  var box = document.getElementById('mediaLightbox');
  var stage = document.getElementById('mediaLightboxStage');
  if (stage) stage.innerHTML = '';
  if (box) box.hidden = true;
}

/* ── Running a check ── */

function buildCheckPayload(platform) {
  var payload = {};
  var form = document.getElementById('form-social');
  if (form && form.querySelectorAll) {
    var flags = form.querySelectorAll('[data-flag]');
    for (var i = 0; i < flags.length; i++) {
      var el = flags[i];
      if (el.type === 'checkbox') {
        if (el.checked) payload[el.getAttribute('data-flag')] = '1';
      } else if (el.value) {
        payload[el.getAttribute('data-flag')] = el.value;
      }
    }
  }
  var burner = loadBurnerConfig();
  var meta = (typeof SOCIAL_META !== 'undefined') && SOCIAL_META ? SOCIAL_META[platform] : null;
  if (burner && burner.enabled && burner.username &&
      meta && meta.login && meta.login !== 'none') {
    payload.burner_enabled = '1';
    payload.burner_username = String(burner.username);
    payload.burner_password = String(burner.password || '');
  }
  return payload;
}

/* ── Scan mode ──
 *
 * While a check runs, the dashboard body is stale (it describes the
 * PREVIOUS check) and the options are already on their way to the
 * server. Showing both under the scan card is how an unchecked target
 * rendered four stacked boxes saying three versions of "nothing yet".
 * During a scan: identity band + scan card. Nothing else.
 * Repaints derive the state from the live scan registry, so a finished,
 * failed or cancelled check always restores the view. */
function setScanMode(scanning) {
  var dash = document.getElementById('socialDash');
  if (dash) dash.hidden = !!scanning;
  var opts = document.getElementById('form-social');
  if (opts) opts.hidden = !!scanning;
}

function refreshScanMode() {
  var scanning = !!activeScans['socialResults'];
  setScanMode(scanning);
  /* The capability line is "why add this tab" — it speaks before a
     target exists and stays quiet once the tab is tracking one. */
  var caps = document.getElementById('socialCaps');
  if (caps) caps.hidden = scanning || dashboardHasTarget;
}

function checkTarget(target) {
  if (!target) {
    showToast('No tracked target on this tab yet — add one on the Targets tab.', 'error');
    return;
  }
  var btn = document.getElementById('socialCheckBtn');
  setLoading(btn, true);
  showScanning('socialResults', socialLabel(target.platform) + ' @' + target.handle,
               false, 'social');
  refreshScanMode();
  runAsyncScan({
    url: '/api/social/targets/' + target.id + '/check',
    method: 'POST',
    body: buildCheckPayload(target.platform),
    resultsId: 'socialResults',
    target: target.handle,
    qtype: 'social',
    btn: btn,
    onFail: function () { refreshScanMode(); },
    onDone: function (result) {
      if (result && result.error) {
        showToast('Check failed: ' + result.error, 'error');
      } else if (result && result.first) {
        showToast('Baseline recorded for @' + target.handle, 'success');
      } else {
        showToast('Check complete', 'success');
      }
      /* Repaint whichever tab is actually open — a check finishing while
         the operator browsed another platform must not repaint that
         platform's head with this target's numbers. The store now
         carries the recomputed diff for this check. */
      var sel = document.getElementById('socialPlatform');
      var showing = (sel && sel.value) ? sel.value : target.platform;
      loadSocialDashboard(showing, target.id);
      loadTargets();
    }
  });
}

/* ── Wiring (script tag sits at the end of body — the DOM exists here) ── */
(function wireTargetsAndCheckAgain() {
  var addBtn = document.getElementById('targetAddBtn');
  if (addBtn) addBtn.addEventListener('click', addTargetFromForm);
  var handleInput = document.getElementById('targetHandle');
  if (handleInput) {
    handleInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); addTargetFromForm(); }
    });
  }
  var list = document.getElementById('targetsList');
  if (list) {
    list.addEventListener('click', function (e) {
      var check = e.target.closest ? e.target.closest('[data-check-id]') : null;
      if (check) {
        openTargetDashboard(parseInt(check.getAttribute('data-check-id'), 10));
        return;
      }
      var del = e.target.closest ? e.target.closest('[data-del-id]') : null;
      if (del) removeTargetFlow(parseInt(del.getAttribute('data-del-id'), 10), del);
    });
  }
  var checkBtn = document.getElementById('socialCheckBtn');
  if (checkBtn) {
    checkBtn.addEventListener('click', function () { checkTarget(dashboardTarget); });
  }
  /* The form carries only per-check options; Enter must not invent a run
     against an unselected target. */
  var form = document.getElementById('form-social');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      checkTarget(dashboardTarget);
    });
  }
  var dash = document.getElementById('socialDash');
  if (dash) {
    dash.addEventListener('click', function (e) {
      if (e.target && e.target.id === 'gotoTargets') { openTargetsPanel(); return; }
      /* Timeline card: rewind the main column to that check. */
      var histRow = e.target.closest ? e.target.closest('[data-hist-index]') : null;
      if (histRow) {
        var idx = parseInt(histRow.getAttribute('data-hist-index'), 10);
        if (!isNaN(idx) && dashboardTarget) {
          dashboardIndex = idx;
          var sel = document.getElementById('socialPlatform');
          paintDashboardSelection((sel && sel.value) || dashboardTarget.platform,
                                  dashboardTarget, dashboardDetail || {});
        }
        return;
      }
      /* Media tile: open the viewer. */
      var tile = e.target.closest ? e.target.closest('[data-media-src]') : null;
      if (tile) {
        openMediaLightbox(tile.getAttribute('data-media-src'),
                          tile.getAttribute('data-media-kind'),
                          tile.getAttribute('data-media-caption'));
        return;
      }
      var toggle = e.target.closest ? e.target.closest('[data-toggle]') : null;
      if (!toggle) return;
      var key = toggle.getAttribute('data-toggle');
      if (key === 'posts') {
        var posts = document.getElementById('socialPosts');
        if (posts) posts.style.display = posts.style.display === 'none' ? '' : 'none';
        return;
      }
      var panel = document.querySelector('#socialDiff [data-list="' + key + '"]');
      if (panel) panel.style.display = panel.style.display === 'none' ? '' : 'none';
    });
  }
  var lightbox = document.getElementById('mediaLightbox');
  if (lightbox) {
    lightbox.addEventListener('click', function (e) {
      if (e.target === lightbox) closeMediaLightbox();
    });
  }
  var lightboxClose = document.getElementById('mediaLightboxClose');
  if (lightboxClose) lightboxClose.addEventListener('click', closeMediaLightbox);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeMediaLightbox();
  });
  ['settingsBurnerEnabled', 'settingsBurnerUser', 'settingsBurnerPass'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', saveBurnerSettings);
  });
})();

/* Preload so the Overview's "Tracked targets" tile is a number, not a
   dash, the moment the dashboard opens. */
loadTargets();
