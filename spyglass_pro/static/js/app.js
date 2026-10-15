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

      if (api === 'social') {
        var platform = (document.getElementById('socialPlatform') || {}).value || '';
        if (!platform) {
          setLoading(btn, false);
          clearScan(resultsId);
          /* The tab sets the platform, so an empty value means the
             registry has not answered yet — not a missing choice. */
          showToast('Platforms are still loading', 'error');
          return;
        }
        var payload = { platform: platform, handle: target };
        Object.keys(flags).forEach(function (k) { payload[k] = flags[k]; });
        /* Keyless adapters (Mastodon, Bluesky) fetch public JSON — browser
           flags are inert server-side, so strip them instead of sending
           options the engine will ignore. */
        if (SOCIAL_META[platform] && !SOCIAL_META[platform].browser) {
          delete payload.headless;
          delete payload.deep;
          delete payload.media;
        }
        var burnerOn = document.getElementById('burnerEnabled');
        var burnerUser = document.getElementById('burnerUser');
        var burnerPass = document.getElementById('burnerPass');
        payload.burner_enabled = !!(burnerOn && burnerOn.checked);
        payload.burner_username = burnerUser ? burnerUser.value.trim() : '';
        payload.burner_password = burnerPass ? burnerPass.value : '';
        if (payload.burner_enabled && (!payload.burner_username || !payload.burner_password)) {
          setLoading(btn, false);
          clearScan(resultsId);
          showToast('Burner login needs a username and password', 'error');
          return;
        }
        runAsyncScan({
          url: '/api/social/run', method: 'POST', body: payload,
          resultsId: resultsId, target: target, qtype: 'social', btn: btn
        });
        return;
      }

      if (api === 'lens') {
        params.set('target', target);
        Object.keys(flags).forEach(function (k) { params.set(k, flags[k]); });
        runAsyncScan({
          url: '/api/lens/run?' + params.toString(), method: 'GET',
          resultsId: resultsId, target: target, qtype: 'lens', btn: btn,
          onDone: function () { if (flags.alsoSpyglass) runSpyglassIp(target, resultsId); }
        });
        return;
      }

      setLoading(btn, false);
      clearScan(resultsId);
      showToast('Unknown API: ' + api, 'error');
    });
  });

  function runSpyglassIp(target, resultsId) {
    showScanning(resultsId, target, true, 'ip');
    runAsyncScan({
      url: '/api/spyglass/run?module=ip&target=' + encodeURIComponent(target),
      method: 'GET', resultsId: resultsId, target: target,
      qtype: 'ip', append: true, btn: null
    });
  }

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
                 website: 'Website', ip: 'IP address', metadata: 'Metadata' };
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
  website: ['dig', 'whois', 'curl'],
  ip: ['shodan'],
  metadata: ['exiftool'],
  opsec: [],
  social: []
};
var PREFLIGHT_KEYS = {
  lens: [['shodan_api_key', 'Shodan'], ['virustotal_api_key', 'VirusTotal'],
         ['abuseipdb_api_key', 'AbuseIPDB'], ['censys_api_key', 'Censys'],
         ['greynoise_api_key', 'GreyNoise'], ['nvd_api_key', 'NVD']],
  ip: [['shodan_api_key', 'Shodan'], ['virustotal_api_key', 'VirusTotal'],
       ['abuseipdb_api_key', 'AbuseIPDB']],
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
  shodan_api_key: 'open ports + org/ISP',
  virustotal_api_key: 'IP reputation votes',
  abuseipdb_api_key: 'abuse confidence score',
  censys_api_key: 'host certs + services',
  greynoise_api_key: 'noise classification',
  nvd_api_key: 'CVE enrichment',
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
    /* No CLI legs and no keys: the panel is the registry. An empty
       tools bit here once rendered "0/0 tools detected", which reads as
       broken rather than keyless. */
    var nplats = ((STATUS && STATUS.platforms) || []).length;
    if (nplats) {
      bits.push(nplats + ' platforms: stealth-browser Instagram + keyless Mastodon/Bluesky');
    } else {
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
      displayResults(resultsId, data, append, qtype);
      if (opts.onDone) opts.onDone(data);
    }
  }).catch(function (err) {
    var scan = activeScans[resultsId];
    if (scan && scan.cancelled) return;
    setLoading(btn, false);
    clearScan(resultsId);
    showToast('Error: ' + err.message, 'error');
  });
}

function finishAsyncScan(opts, result) {
  var scan = activeScans[opts.resultsId];
  if (scan && scan.cancelled) return;
  setLoading(opts.btn || null, false);
  displayResults(opts.resultsId, result, !!opts.append, opts.qtype || '');
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
    cur.pollTimer = setTimeout(function () { pollJob(jobId, opts, seen); }, 3000);
  });
}

function displayResults(containerId, data, append, qtype) {
  clearScan(containerId);
  var container = document.getElementById(containerId);
  if (!container) return;

  var html;
  if (!data || (typeof data === 'object' && Object.keys(data).length === 0)) {
    html = '<div class="result-card"><p class="dim">No results returned.</p></div>';
  } else if (data.error) {
    html = '<div class="result-card"><p class="status-err">Error: ' + escapeHtml(data.error) + '</p></div>';
  } else {
    html = '<div class="result-card">';
    if (data.summary) {
      html += '<h4>' + escapeHtml(data.summary) + '</h4>';
    }
    if (Array.isArray(data.progress) && data.progress.length) {
      html += '<div class="run-log"><span class="run-log-title">Run log</span>';
      data.progress.forEach(function (line) {
        html += '<div class="run-log-line">' + escapeHtml(line) + '</div>';
      });
      html += '</div>';
    }
    if (Array.isArray(data.artifacts) && data.artifacts.length) {
      html += '<div class="artifact-list"><span class="run-log-title">Artifacts</span>';
      data.artifacts.forEach(function (a) {
        html += '<div class="artifact-item"><span class="artifact-kind">' + escapeHtml(a.kind) +
                '</span><code>' + escapeHtml(a.path) + '</code></div>';
      });
      html += '</div>';
    }
    if (data.stored_run_id) {
      html += '<div class="artifact-list"><span class="run-log-title">Stored</span>' +
              '<div class="artifact-item"><span class="artifact-kind">case</span>' +
              '<code>run #' + escapeHtml(String(data.stored_run_id)) +
              ' — visible under Stored Cases</code></div></div>';
    }
    if (data.normalized) {
      html += renderNormalized(data.normalized);
    }
    html += renderBody(data, qtype || '');
    var raw = typeof data === 'object' ? JSON.stringify(data, null, 2) : String(data);
    html += '<details class="raw-json"><summary>Raw JSON</summary><pre>' + escapeHtml(raw) + '</pre></details>';
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
    render: renderSocial },
  { name: 'investigate', matches: function (d, q) { return q === 'investigate' || d.entities !== undefined; },
    render: renderInvestigate },
  { name: 'lens',       matches: function (d) { return d.resolved_ip !== undefined || d.input_type !== undefined; },
    render: renderLens },
  { name: 'opsec',      matches: function (d) { return d.direct !== undefined && d.recommendations !== undefined; },
    render: renderOpsec },
  { name: 'phone',      matches: function (d) { return d.phonenumbers !== undefined; },
    render: renderPhone },
  { name: 'website',    matches: function (d) { return d.subdomains !== undefined; },
    render: renderWebsite },
  { name: 'darkweb',    matches: function (d) { return d.ahmia !== undefined; },
    render: renderDarkweb },
  { name: 'username',   matches: function (d) { return d.all_4 !== undefined; },
    render: renderUsername },
  { name: 'email',      matches: function (d) { return d.user_scanner_only !== undefined; },
    render: renderEmail },
  /* Matched on geo/hostname/a_records: open_ports went with the nmap scan,
     so keying on it meant this renderer never fired. */
  { name: 'ip',         matches: function (d) {
      return d.geo !== undefined || d.hostname !== undefined || d.a_records !== undefined; },
    render: renderSpyglassIp }
];

function renderBody(data, qtype) {
  for (var i = 0; i < RENDERERS.length; i++) {
    var entry = RENDERERS[i];
    if (entry.matches(data, qtype)) return entry.render(data, qtype);
  }
  return renderGeneric(data);
}

/* ── Social (registry-driven, one layout for every platform) ── */
/* Mirror of PROFILE_FIELDS in spyglass_pro/social/schema.py — the field
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

function socialCell(field, value) {
  if (field.type === 'count' && typeof value === 'number') {
    return value.toLocaleString();
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
  var label = (d.platform || 'social').toUpperCase();

  html += '<h3>' + escapeHtml(label) + ' — @' + escapeHtml(d.handle || '') + '</h3>';

  if (d.error) {
    html += '<p class="res-line">Error: <span class="status-err">' +
            escapeHtml(d.error) + '</span></p>';
  }
  html += renderStatusLine('Session', d.logged_in ? 'burner logged in' : 'logged out', !!d.logged_in);
  html += renderStatusLine('Source', d.source || 'n/a', !!d.source);

  if (d.avatar_url && safeHref(d.avatar_url)) {
    html += '<p class="res-line"><img class="social-avatar" src="' +
            escapeHtml(safeHref(d.avatar_url)) + '" alt="" /></p>';
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
      if (post.likes !== undefined && post.likes !== null) meta.push(post.likes + ' likes');
      if (post.comments !== undefined && post.comments !== null) meta.push(post.comments + ' comments');
      html += '<li>' + (href ? '<a href="' + escapeHtml(href) + '" target="_blank" rel="noopener">' +
                          caption + '</a>' : caption);
      if (meta.length) html += ' <span class="dim">(' + escapeHtml(meta.join(' · ')) + ')</span>';
      html += '</li>';
    });
    html += '</ul>';
  }

  /* Walls are the honest counterpart of an empty list. */
  var walls = d.walls || {};
  var wallKeys = Object.keys(walls);
  if (wallKeys.length) {
    html += '<h4>Not retrieved</h4>';
    wallKeys.forEach(function (kind) {
      html += renderStatusLine(walls[kind].label || kind, walls[kind].why || 'unavailable', false);
    });
  }

  if (d.metrics && Object.keys(d.metrics).length) {
    html += '<h4>Collected</h4>';
    Object.keys(d.metrics).sort().forEach(function (name) {
      html += renderStatusLine(name.replace(/_/g, ' '), d.metrics[name], true);
    });
  }

  if (d.notes && d.notes.length) {
    html += '<h4>Notes</h4>';
    d.notes.forEach(function (note) { html += '<p class="res-line">' + escapeHtml(note) + '</p>'; });
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

function selectSocialPlatform(key) {
  var sel = document.getElementById('socialPlatform');
  if (!sel) { pendingSocialPlatform = key; return; }
  if (!SOCIAL_LABELS[key]) { pendingSocialPlatform = key; return; }
  pendingSocialPlatform = null;
  sel.value = key;
  var name = document.getElementById('socialPlatformName');
  if (name) name.textContent = SOCIAL_LABELS[key];
  setSocialPlaceholder(key);
  updateSocialCaps(null);
}

function setSocialPlaceholder(key) {
  var input = document.getElementById('socialHandle');
  if (!input) return;
  var hints = {
    instagram: 'instagram username',
    mastodon: 'user or user@instance',
    bluesky: 'user.bsky.social'
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
      /* Default to the first tab's platform unless a tab was already
         clicked while the registry was in flight. */
      var want = pendingSocialPlatform || sel.value || 'instagram';
      pendingSocialPlatform = null;
      if (!SOCIAL_LABELS[want]) want = list[0].key;
      sel.value = want;
      var name = document.getElementById('socialPlatformName');
      if (name) name.textContent = SOCIAL_LABELS[want];
      setSocialPlaceholder(want);
      showCaps(list, want);
    })
    .catch(function () {
      sel.value = '';
    });
}

function updateSocialCaps(platforms) {
  var caps = document.getElementById('socialCaps');
  var sel = document.getElementById('socialPlatform');
  if (!caps || !sel || !sel.value) return;
  if (!platforms) {
    return apiFetch('/api/social/platforms').then(function (r) { return r.json(); })
      .then(function (list) { showCaps(list, sel.value); });
  }
  showCaps(platforms, sel.value);
}

function showCaps(platforms, key) {
  var caps = document.getElementById('socialCaps');
  if (!caps) return;
  var match = (platforms || []).filter(function (p) { return p.key === key; })[0];
  var keyless = !!match && match.browser === false;
  /* Burner login only exists on browser platforms that declare it —
     keyless adapters (Mastodon, Bluesky) have no login row to show. */
  var burnerRow = document.getElementById('burnerRow');
  if (burnerRow) burnerRow.style.display = (match && match.login && match.login !== 'none') ? '' : 'none';
  /* Headless / Deep / Download Media drive the stealth browser, which
     keyless adapters never launch — offering them there implies stories
     and media downloads that do not exist on those tabs. */
  var form = document.getElementById('form-social');
  var browserOpts = form ? form.querySelectorAll('[data-browser-only]') : [];
  for (var i = 0; i < browserOpts.length; i++) {
    browserOpts[i].style.display = keyless ? 'none' : '';
  }
  if (!match) { caps.textContent = ''; return; }
  caps.textContent = 'Can return: ' + match.capabilities.join(', ') +
    (match.login === 'none' ? (match.browser === false ? ' · keyless, no browser needed' : ' · no burner login') : ' · burner login supported');
}

function renderSection(title, inner) {
  if (!inner) return '';
  return '<div class="res-section"><span class="res-section-title">' +
         escapeHtml(title) + '</span>' + inner + '</div>';
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

/* ── Spyglass-OSINT: email ── */
function renderEmail(d) {
  var html = '';
  var groups = [
    ['both', 'Found by multiple engines'],
    ['user_scanner_only', 'user-scanner only'],
    ['holehe_only', 'holehe only'],
    ['blackbird_only', 'blackbird only']
  ];
  groups.forEach(function (g) {
    if (d[g[0]] && d[g[0]].length) {
      html += renderSection(g[1] + ' (' + d[g[0]].length + ')', renderLinkTable(d[g[0]]));
    }
  });
  if (d.breach) html += renderSection('Breach check', renderBreach(d.breach));
  return html || renderGeneric(d);
}

/* ── Spyglass-OSINT: username ── */
function renderUsername(d) {
  var order = [
    ['all_4', 'All 4 engines agree'],
    ['all_3_no_bb', '3 of 4 (no blackbird)'],
    ['all_3_no_mg', '3 of 4 (no maigret)'],
    ['all_3_no_sh', '3 of 4 (no sherlock)'],
    ['all_3_no_us', '3 of 4 (no user-scanner)'],
    ['us+sherlock', 'user-scanner + sherlock'],
    ['us+maigret', 'user-scanner + maigret'],
    ['us+blackbird', 'user-scanner + blackbird'],
    ['sherlock+maigret', 'sherlock + maigret'],
    ['sherlock+blackbird', 'sherlock + blackbird'],
    ['maigret+blackbird', 'maigret + blackbird'],
    ['us_only', 'user-scanner only'],
    ['sherlock_only', 'sherlock only'],
    ['maigret_only', 'maigret only'],
    ['blackbird_only', 'blackbird only']
  ];
  var html = '';
  var shown = 0;
  order.forEach(function (g) {
    if (d[g[0]] && d[g[0]].length) {
      html += renderSection(g[1] + ' (' + d[g[0]].length + ')', renderLinkTable(d[g[0]]));
      shown += d[g[0]].length;
    }
  });
  if (d.breach) html += renderSection('Breach check', renderBreach(d.breach));
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
    }));
  }
  if (d.phoneinfoga && Object.keys(d.phoneinfoga).length) {
    html += renderSection('PhoneInfoga', renderKv(d.phoneinfoga));
  }
  if (Array.isArray(d.ignorant) && d.ignorant.length) {
    html += renderSection('Web mentions', renderLinkTable(
      d.ignorant.map(function (u) { return { domain: u, url: u }; }), 20));
  }
  if (d.breach) html += renderSection('Breach check', renderBreach(d.breach));
  return html || renderGeneric(d);
}

/* ── Spyglass-OSINT: website ── */
function renderWebsite(d) {
  var html = '';
  if (d.title) html += renderStatusLine('Page title', d.title, true);
  if (d.status_code) html += renderStatusLine('HTTP status', d.status_code, true);
  if (Array.isArray(d.subdomains) && d.subdomains.length) {
    html += renderSection('Subdomains (' + d.subdomains.length + ')', renderChips(d.subdomains));
  }
  if (d.dns) html += renderSection('DNS', renderKv(d.dns));
  if (d.whois) html += renderSection('WHOIS', renderKv(d.whois));
  if (d.shodan) html += renderSection('Shodan', renderKv(d.shodan));
  html += renderGeneric(d, ['title', 'status_code', 'subdomains', 'dns', 'whois',
                            'shodan', 'dns_records', 'wildcard_dns',
                            'dns_email_security', 'history']);
  return html;
}

/* ── Spyglass-OSINT: ip ── */
function renderSpyglassIp(d) {
  var html = '';
  if (d.geo) html += renderSection('GeoIP', renderKv(d.geo));
  if (d.whois) html += renderSection('WHOIS', renderKv(d.whois));
  if (d.hostname) html += renderSection('Reverse DNS', renderKv({hostname: d.hostname}));
  if (Array.isArray(d.a_records) && d.a_records.length) {
    html += renderSection('A records', renderChips(d.a_records));
  }
  if (d.shodan) {
    var ports = Array.isArray(d.shodan.ports) ? d.shodan.ports : null;
    if (ports && ports.length) {
      html += renderSection('Open ports (Shodan)', renderChips(ports));
    }
    if (d.shodan.hostnames) {
      html += renderSection('Hostnames (Shodan)', renderChips(d.shodan.hostnames));
    }
  }
  html += renderGeneric(d, ['geo', 'whois', 'hostname', 'a_records', 'shodan', 'ip']);
  return html;
}

/* ── Spyglass-OSINT: darkweb ── */
function renderDarkweb(d) {
  var html = '';
  if (Array.isArray(d.ahmia) && d.ahmia.length) {
    html += renderSection('Ahmia index hits (' + d.ahmia.length + ')',
      renderLinkTable(d.ahmia.map(function (h) {
        return { domain: h.title || h.name || h, url: h.url || h.link || '' };
      }), 20));
  } else if (d.ahmia) {
    html += renderStatusLine('Ahmia index', 'no hits', false);
  }
  if (d.breach) html += renderSection('Breach check', renderBreach(d.breach));
  if (d.pwned !== undefined) {
    html += renderStatusLine('Have I Been Pwned', d.pwned ? 'PWNED (' + d.count + ' breaches)' : 'not found', !d.pwned);
  }
  html += renderGeneric(d, ['ahmia', 'breach', 'pwned', 'count', 'query', 'type']);
  return html;
}

/* ── Spyglass-OSINT: opsec ── */
function renderOpsec(d) {
  var html = '';
  if (d.direct) {
    html += renderSection('Direct connection (no proxy)', renderKv(d.direct));
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
      }).join('') + '</ul>');
  }
  html += renderGeneric(d, ['direct', 'proxy_configured', 'dns_leak', 'recommendations']);
  return html;
}

/* ── Lens-Extender ── */
function renderLens(d) {
  var html = '';
  html += renderKv(d, {target: 'Target', input_type: 'Input type', resolved_ip: 'Resolved IP',
                       reverse_dns: 'Reverse DNS', shodan_org: 'Shodan org', shodan_isp: 'Shodan ISP'});
  if (d.geo) html += renderSection('GeoIP', renderKv(d.geo));
  if (d.rdap) html += renderSection('RDAP', renderKv(d.rdap));
  if (Array.isArray(d.ports) && d.ports.length) {
    html += renderSection('Ports (' + d.ports.length + ')',
      '<table class="res-table"><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead><tbody>' +
      d.ports.map(function (p) {
        return '<tr><td>' + escapeHtml(String(p.port)) + '</td><td>' + escapeHtml(String(p.protocol)) + '</td><td>' +
               escapeHtml(String(p.service || '—')) + '</td><td>' + escapeHtml(String(p.version || '—')) + '</td></tr>';
      }).join('') + '</tbody></table>');
  }
  if (Array.isArray(d.software) && d.software.length) {
    html += renderSection('Software (' + d.software.length + ')',
      '<table class="res-table"><thead><tr><th>Type</th><th>Vendor</th><th>Product</th><th>Version</th></tr></thead><tbody>' +
      d.software.map(function (s) {
        return '<tr><td>' + escapeHtml(String(s.type || '—')) + '</td><td>' + escapeHtml(String(s.vendor || '—')) + '</td><td>' +
               escapeHtml(String(s.product || '—')) + '</td><td>' + escapeHtml(String(s.version || '—')) + '</td></tr>';
      }).join('') + '</tbody></table>');
  }
  if (Array.isArray(d.vulns) && d.vulns.length) {
    html += renderSection('Vulnerabilities (' + d.vulns.length + ')',
      '<ul class="res-list">' + d.vulns.map(function (v) {
        return '<li>' + escapeHtml(typeof v === 'object' ? JSON.stringify(v) : String(v)) + '</li>';
      }).join('') + '</ul>');
  }
  if (Array.isArray(d.tags) && d.tags.length) html += renderSection('Tags', renderChips(d.tags));
  if (Array.isArray(d.hostnames) && d.hostnames.length) html += renderSection('Hostnames', renderChips(d.hostnames));
  if (Array.isArray(d.os_guesses) && d.os_guesses.length) html += renderSection('OS guesses', renderChips(d.os_guesses));
  if (d.dns_records) html += renderSection('DNS records', renderKv(d.dns_records));
  if (Array.isArray(d.errors) && d.errors.length) {
    html += renderSection('Probe errors',
      '<ul class="res-list">' + d.errors.map(function (e) {
        return '<li>' + escapeHtml(String(e)) + '</li>';
      }).join('') + '</ul>');
  }
  html += renderGeneric(d, ['target', 'input_type', 'resolved_ip', 'reverse_dns', 'hostnames',
                            'shodan_org', 'shodan_isp', 'shodan_hostnames', 'http_profiles',
                            'tls_profiles', 'fcrdns', 'geo', 'rdap', 'ports', 'host_scripts',
                            'os_guesses', 'software', 'tags', 'cpes', 'certs', 'vulns',
                            'ripestat', 'greynoise', 'freshness', 'dnsbl', 'dns_records',
                            'cohosted', 'abuseipdb', 'virustotal', 'whois_domain', 'errors']);
  return html;
}

/* ── Cross-tool investigation ──
 *
 * Matches sort first: they are the verdict, info rows are context. A
 * matched value also lights up wherever it appears in the entity chips,
 * so the link between "correlated" and "where" needs no scrolling. The
 * graph is a summary visual only — center is the queried input, ring
 * nodes are entity kinds with real counts, nothing weighted or inferred. */
function renderInvestigate(d) {
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
    var entHtml = renderEntityGraph(d);
    [['emails', 'Emails'], ['domains', 'Domains'], ['ips', 'IP addresses'],
     ['phones', 'Phone numbers'], ['orgs', 'Organizations'], ['asns', 'ASNs']].forEach(function (pair) {
      var values = d.entities[pair[0]];
      if (Array.isArray(values) && values.length) {
        entHtml += '<p class="res-line dim">' + pair[1] + ':</p>' + matchChips(values, matchValues);
      }
    });
    html += renderSection('Entities', entHtml);
  }
  if (Array.isArray(d.correlations) && d.correlations.length) {
    var corrs = d.correlations.slice().sort(function (a, b) {
      return ((b && b.type === 'match') - (a && a.type === 'match'));
    });
    var matches = corrs.filter(function (c) { return c && c.type === 'match'; }).length;
    html += renderSection('Correlations (' + corrs.length + (matches ? ', ' + matches + ' match' +
      (matches === 1 ? '' : 'es') : '') + ')',
      '<ul class="res-list corr-list">' + corrs.map(function (c) {
        var isMatch = c.type === 'match';
        var out = '<li class="' + (isMatch ? 'corr-match' : '') + '">' +
          (isMatch ? '<span class="artifact-kind">match</span> ' : '') +
          '<strong>' + escapeHtml(c.desc || c.type || '') + '</strong>';
        if (c.detail) out += '<br>' + corrDetailChips(String(c.detail), isMatch);
        return out + '</li>';
      }).join('') + '</ul>');
  }
  if (d.results && typeof d.results === 'object') {
    Object.keys(d.results).forEach(function (key) {
      var sub = d.results[key];
      if (!sub || typeof sub !== 'object' || sub.error) return;
      html += renderSection(key + ' (spyglass)', renderBody(sub, key));
    });
  }
  if (d.ip_recon && !d.ip_recon.error) {
    html += renderSection('IP recon (Lens-Extender)', renderBody(d.ip_recon, 'lens'));
  }
  if (d.social && !d.social.error) {
    var socialLabel = (d.social.platform || 'social').toUpperCase();
    html += renderSection(socialLabel + ' profile', renderBody(d.social, 'social'));
  }
  html += renderGeneric(d, ['inputs', 'entities', 'correlations', 'results',
                            'ip_recon', 'social', 'progress', 'summary']);
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
    if (k && data) k.textContent = (data.configured || 0) + '/' + (data.total || 9);
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
  { label: 'Website', tools: ['dig', 'whois', 'curl'] },
  { label: 'IP address', tools: ['shodan'] },
  { label: 'Dark web', keys: [['intelx_api_key', 'IntelX'], ['hibp_api_key', 'HIBP']], note: 'Ahmia + breach keyless' },
  { label: 'Enrichment', keys: [['shodan_api_key', 'Shodan'], ['virustotal_api_key', 'VirusTotal'], ['abuseipdb_api_key', 'AbuseIPDB'], ['censys_api_key', 'Censys'], ['greynoise_api_key', 'GreyNoise'], ['nvd_api_key', 'NVD']] },
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
    if (k && data) k.textContent = (data.configured || 0) + '/' + (data.total || 9);
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
      data.forEach(function (c) {
        html += '<tr class="case-row" data-target="' + escapeHtml(c.target) +
                '" data-qtype="' + escapeHtml(c.qtype) +
                '" title="Load this target\'s timeline"><td>' + escapeHtml(c.target) +
                '</td><td>' + escapeHtml(c.qtype) + '</td><td>' + c.id + '</td><td>' +
                escapeHtml(c.run_at) + '</td>' +
                '<td class="case-del-cell"><button type="button" class="case-del" data-del-id="' + c.id +
                '" data-del-qtype="' + escapeHtml(c.qtype) +
                '" title="Delete this stored run">✕</button></td></tr>';
      });
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
  if (!window.confirm('Delete stored run #' + runId + ' (' + (qtype || 'unknown type') + ')? Its entities leave the index too.')) return;
  if (btn) btn.disabled = true;
  apiFetch('/api/cases/run?id=' + encodeURIComponent(runId) + '&qtype=' + encodeURIComponent(qtype || ''), {
    method: 'DELETE'
  }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
    .then(function (res) {
      if (!res.ok) { showToast('Error: ' + (res.data.error || 'delete failed'), 'error'); return; }
      showToast('Deleted stored run #' + runId, 'success');
      loadCases();
    }).catch(function (err) {
      showToast('Error: ' + err.message, 'error');
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
          escapeHtml(d.old_run || '?') + '</span> → <span class="status-ok">' +
          escapeHtml(d.new_run || '?') + '</span></p>';
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
    html += '<tr><td>' + escapeHtml(run.run_at) + '</td><td>' + escapeHtml(run.qtype) +
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
