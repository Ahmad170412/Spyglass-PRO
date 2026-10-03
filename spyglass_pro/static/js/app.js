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
  }

  navItems.forEach(function (item) {
    item.addEventListener('click', function () {
      activatePanel(item.getAttribute('data-panel'));
    });
  });

  /* ── IP panel: active scan reveals port spec ── */
  var lensActive = document.getElementById('lensActive');
  var lensPortsRow = document.getElementById('lensPortsRow');
  if (lensActive && lensPortsRow) {
    lensActive.addEventListener('change', function () {
      lensPortsRow.style.display = lensActive.checked ? 'block' : 'none';
    });
  }

  /* ── Proxy ── */
  var proxyInput = document.getElementById('proxyInput');
  var proxyApply = document.getElementById('proxyApply');
  var proxyClear = document.getElementById('proxyClear');
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

  if (proxyApply && proxyInput) {
    proxyApply.addEventListener('click', function () {
      apiFetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy: proxyInput.value.trim() })
      }).then(function (r) { return r.json(); }).then(function (data) {
        updateProxyUI(data.proxy);
        showToast('Proxy updated: ' + (data.proxy || 'none'), 'success');
      }).catch(function (err) {
        showToast('Error: ' + err.message, 'error');
      });
    });
  }

  if (proxyClear && proxyInput) {
    proxyClear.addEventListener('click', function () {
      proxyInput.value = '';
      apiFetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy: '' })
      }).then(function (r) { return r.json(); }).then(function () {
        updateProxyUI(null);
        showToast('Proxy cleared', 'info');
      }).catch(function (err) {
        showToast('Error: ' + err.message, 'error');
      });
    });
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
      showScanning(resultsId, target);

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
        apiFetch('/api/investigate/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        }).then(function (r) { return r.json(); })
          .then(function (data) { setLoading(btn, false); displayResults(resultsId, data, false, 'investigate'); })
          .catch(function (err) { setLoading(btn, false); clearScan(resultsId); showToast('Error: ' + err.message, 'error'); });
        return;
      }

      var params = new URLSearchParams();
      if (api === 'spyglass') {
        params.set('module', qtype);
        params.set('target', target);
        Object.keys(flags).forEach(function (k) { params.set(k, flags[k]); });
        apiFetch('/api/spyglass/run?' + params.toString())
          .then(function (r) { return r.json(); })
          .then(function (data) { setLoading(btn, false); displayResults(resultsId, data, false, qtype); })
          .catch(function (err) { setLoading(btn, false); clearScan(resultsId); showToast('Error: ' + err.message, 'error'); });
        return;
      }

      if (api === 'instacloak') {
        var payload = { username: target };
        Object.keys(flags).forEach(function (k) { payload[k] = flags[k]; });
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
        apiFetch('/api/instacloak/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        })
          .then(function (r) { return r.json(); })
          .then(function (data) { setLoading(btn, false); displayResults(resultsId, data, false, 'instagram'); })
          .catch(function (err) { setLoading(btn, false); clearScan(resultsId); showToast('Error: ' + err.message, 'error'); });
        return;
      }

      if (api === 'lens') {
        params.set('target', target);
        Object.keys(flags).forEach(function (k) { params.set(k, flags[k]); });
        apiFetch('/api/lens/run?' + params.toString())
          .then(function (r) { return r.json(); })
          .then(function (data) {
            setLoading(btn, false);
            displayResults(resultsId, data, false, 'lens');
            if (flags.alsoSpyglass) runSpyglassIp(target, resultsId);
          })
          .catch(function (err) { setLoading(btn, false); clearScan(resultsId); showToast('Error: ' + err.message, 'error'); });
        return;
      }

      setLoading(btn, false);
      clearScan(resultsId);
      showToast('Unknown API: ' + api, 'error');
    });
  });

  function runSpyglassIp(target, resultsId) {
    showScanning(resultsId, target, true);
    apiFetch('/api/spyglass/run?module=ip&target=' + encodeURIComponent(target))
      .then(function (r) { return r.json(); })
      .then(function (data) { displayResults(resultsId, data, true, 'ip'); })
      .catch(function (err) { clearScan(resultsId); showToast('Error: ' + err.message, 'error'); });
  }

  /* ── Load status on startup ── */
  apiFetch('/api/status').then(function (r) { return r.json(); }).then(function (data) {
    updateProxyUI(data.proxy || '');
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
  var caseButtons = [
    ['casesDiffBtn', 'diff'],
    ['casesTimelineBtn', 'timeline'],
    ['casesProfileBtn', 'profile']
  ];
  caseButtons.forEach(function (pair) {
    var btn = document.getElementById(pair[0]);
    if (btn) btn.addEventListener('click', function () { casesQuery(pair[1]); });
  });

  /* ── Load cases ── */
  loadCases();
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

/* ── In-progress scanning card ── */
var SCAN_VERBS = ['Scanning', 'Probing', 'Enumerating', 'Correlating', 'Analyzing', 'Fingerprinting', 'Verifying'];
var activeScans = {};

function fmtElapsed(ms) {
  var s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
}

function clearScan(resultsId) {
  var scan = activeScans[resultsId];
  if (scan) {
    clearInterval(scan.timer);
    clearInterval(scan.verbTimer);
    delete activeScans[resultsId];
  }
  var card = document.getElementById('scanning-' + resultsId);
  if (card) card.remove();
}

function showScanning(resultsId, target, append) {
  clearScan(resultsId);
  var container = document.getElementById(resultsId);
  if (!container) return;
  var start = Date.now();
  var verbIdx = 0;
  var safeTarget = target ? String(target).slice(0, 120) : '';
  var html = '<div class="result-card scan-card" id="scanning-' + resultsId + '">' +
    '<div class="scan-radar"><span></span><span></span><span></span><i></i></div>' +
    '<div class="scan-title">Scan in progress</div>' +
    (safeTarget ? '<div class="scan-target">' + escapeHtml(safeTarget) + '</div>' : '') +
    '<div class="scan-status"><span class="scan-verb">Scanning</span><span class="ellipsis"></span></div>' +
    '<div class="scan-bar"><span></span></div>' +
    '<div class="scan-shimmer w70"></div>' +
    '<div class="scan-shimmer w45"></div>' +
    '<div class="scan-timer">0s elapsed</div>' +
    '</div>';
  if (append) container.insertAdjacentHTML('afterbegin', html);
  else container.innerHTML = html;
  var card = document.getElementById('scanning-' + resultsId);
  var verbEl = card ? card.querySelector('.scan-verb') : null;
  var timerEl = card ? card.querySelector('.scan-timer') : null;
  activeScans[resultsId] = {
    timer: setInterval(function () {
      if (timerEl) timerEl.textContent = fmtElapsed(Date.now() - start) + ' elapsed';
    }, 1000),
    verbTimer: setInterval(function () {
      verbIdx = (verbIdx + 1) % SCAN_VERBS.length;
      if (verbEl) verbEl.textContent = SCAN_VERBS[verbIdx];
    }, 2400)
  };
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
}

/* ── Structured result rendering ── */
function renderBody(data, qtype) {
  if (data.tool === 'InstaCloak' || data.profile_status !== undefined) {
    return renderInstacloak(data);
  }
  if (qtype === 'investigate' || data.entities !== undefined) {
    return renderInvestigate(data);
  }
  if (data.resolved_ip !== undefined || data.input_type !== undefined) {
    return renderLens(data);
  }
  if (data.direct !== undefined && data.recommendations !== undefined) {
    return renderOpsec(data);
  }
  if (data.phonenumbers !== undefined) {
    return renderPhone(data);
  }
  if (data.subdomains !== undefined) {
    return renderWebsite(data);
  }
  if (data.ahmia !== undefined) {
    return renderDarkweb(data);
  }
  if (data.all_4 !== undefined) {
    return renderUsername(data);
  }
  if (data.user_scanner_only !== undefined) {
    return renderEmail(data);
  }
  if (Array.isArray(data.open_ports)) {
    return renderSpyglassIp(data);
  }
  return renderGeneric(data);
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

function renderChips(items) {
  if (!items || !items.length) return '';
  var html = '<div class="chip-group">';
  items.forEach(function (item) {
    html += '<span class="chip">' + escapeHtml(String(item)) + '</span>';
  });
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
  if (d.headers) html += renderSection('Response headers', renderKv(d.headers));
  if (Array.isArray(d.technologies) && d.technologies.length) {
    html += renderSection('Technologies', renderChips(d.technologies));
  }
  if (Array.isArray(d.ports) && d.ports.length) {
    html += renderSection('Open ports', renderChips(d.ports));
  }
  if (Array.isArray(d.directories) && d.directories.length) {
    html += renderSection('Interesting paths', renderChips(d.directories));
  }
  html += renderGeneric(d, ['title', 'status_code', 'subdomains', 'dns', 'whois',
                            'headers', 'technologies', 'ports', 'directories']);
  return html;
}

/* ── Spyglass-OSINT: ip ── */
function renderSpyglassIp(d) {
  var html = '';
  if (d.geo) html += renderSection('GeoIP', renderKv(d.geo));
  if (d.whois) html += renderSection('WHOIS', renderKv(d.whois));
  if (Array.isArray(d.open_ports) && d.open_ports.length) {
    html += renderSection('Open ports (' + d.open_ports.length + ')', renderChips(d.open_ports));
  }
  if (d.reverse_dns) html += renderStatusLine('Reverse DNS', d.reverse_dns, true);
  html += renderGeneric(d, ['geo', 'whois', 'open_ports', 'reverse_dns']);
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

/* ── InstaCloak ── */
function renderInstacloak(d) {
  var html = '';
  var p = d.profile || {};
  var counts = p.counts || {};
  var statBits = [];
  if (counts.followers !== undefined && counts.followers !== null) statBits.push(counts.followers + ' followers');
  if (counts.following !== undefined && counts.following !== null) statBits.push(counts.following + ' following');
  if (counts.posts !== undefined && counts.posts !== null) statBits.push(counts.posts + ' posts');
  if (p.full_name) statBits.unshift(p.full_name);
  if (statBits.length) {
    html += '<p class="res-line res-headline">' + escapeHtml(statBits.join(' — ')) + '</p>';
  }
  if (p.biography) html += '<p class="res-line">' + escapeHtml(p.biography) + '</p>';
  var flags = [];
  if (p.is_private) flags.push('private account');
  if (p.verified) flags.push('verified');
  if (d.profile_status && d.profile_status !== 'ok') flags.push('status: ' + d.profile_status);
  if (flags.length) html += renderChips(flags);
  html += renderKv(p, {pk_id: 'ID', profile_pic_url: 'Profile picture'});

  if (Array.isArray(d.posts) && d.posts.length) {
    var rows = d.posts.slice(0, 20).map(function (post) {
      var caption = (post.caption || '').split('\n')[0];
      if (caption.length > 90) caption = caption.slice(0, 90) + '…';
      return '<tr><td>' + (caption ? escapeHtml(caption) : '<span class="dim">no caption</span>') + '</td>' +
             '<td>' + escapeHtml(String(post.like_count !== undefined ? post.like_count : '—')) + '</td>' +
             '<td>' + escapeHtml(String((post.comments || []).length)) + '</td></tr>';
    }).join('');
    html += renderSection('Posts (' + d.posts.length + ')',
      '<table class="res-table"><thead><tr><th>Caption</th><th>Likes</th><th>Comments</th></tr></thead><tbody>' +
      rows + '</tbody></table>');
  }
  if (d.contacts && (d.contacts.emails && d.contacts.emails.length ||
                     d.contacts.phones && d.contacts.phones.length)) {
    var contactHtml = '';
    if (d.contacts.emails && d.contacts.emails.length) {
      contactHtml += renderChips(d.contacts.emails);
    }
    if (d.contacts.phones && d.contacts.phones.length) {
      contactHtml += renderChips(d.contacts.phones);
    }
    html += renderSection('Contacts', contactHtml);
  }
  [['hashtags', 'Top hashtags'], ['mentions', 'Top mentions'], ['commenters', 'Top commenters']].forEach(function (pair) {
    var obj = d[pair[0]];
    if (obj && Object.keys(obj).length) {
      var top = Object.keys(obj).slice(0, 10);
      html += renderSection(pair[1],
        '<ul class="res-list res-rank">' + top.map(function (k) {
          return '<li>' + escapeHtml(k) + ' <span class="dim">×' + obj[k] + '</span></li>';
        }).join('') + '</ul>');
    }
  });
  if (Array.isArray(d.tagged_users) && d.tagged_users.length) {
    html += renderSection('Tagged users', renderChips(d.tagged_users.slice(0, 30)));
  }
  if (Array.isArray(d.locations) && d.locations.length) {
    html += renderSection('Locations', renderChips(
      d.locations.map(function (l) { return l.name || String(l); }).slice(0, 30)));
  }
  ['followers', 'following'].forEach(function (key) {
    var f = d[key];
    if (!f) return;
    var status = f.walled ? 'login-walled' : (f.skipped ? 'skipped' : 'collected');
    html += renderStatusLine(key + ' list', f.collected + ' collected (' + status +
      (f.count !== undefined && f.count !== null ? ', profile says ' + f.count : '') + ')', !f.walled);
  });
  if (Array.isArray(d.notes) && d.notes.length) {
    html += renderSection('Notes',
      '<ul class="res-list">' + d.notes.map(function (n) {
        return '<li>' + escapeHtml(n) + '</li>';
      }).join('') + '</ul>');
  }
  html += renderGeneric(d, ['tool', 'version', 'target', 'run_at', 'duration_seconds',
                            'profile_status', 'profile', 'posts_count', 'posts', 'contacts',
                            'hashtags', 'mentions', 'locations', 'commenters', 'tagged_users',
                            'followers', 'following', 'notes']);
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

/* ── Cross-tool investigation ── */
function renderInvestigate(d) {
  var html = '';
  if (d.entities) {
    var entHtml = '';
    [['emails', 'Emails'], ['domains', 'Domains'], ['ips', 'IP addresses'],
     ['phones', 'Phone numbers'], ['orgs', 'Organizations'], ['asns', 'ASNs']].forEach(function (pair) {
      var values = d.entities[pair[0]];
      if (Array.isArray(values) && values.length) {
        entHtml += '<p class="res-line dim">' + pair[1] + ':</p>' + renderChips(values);
      }
    });
    html += renderSection('Entities', entHtml);
  }
  if (Array.isArray(d.correlations) && d.correlations.length) {
    html += renderSection('Correlations (' + d.correlations.length + ')',
      '<ul class="res-list">' + d.correlations.map(function (c) {
        var badge = c.type === 'match' ? '<span class="artifact-kind">match</span> ' : '';
        return '<li>' + badge + '<strong>' + escapeHtml(c.desc || c.type || '') + '</strong>' +
               (c.detail ? '<br><span class="dim">' + escapeHtml(c.detail) + '</span>' : '') + '</li>';
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
  if (d.instacloak && !d.instacloak.error) {
    html += renderSection('Instagram (InstaCloak)', renderBody(d.instacloak, 'instagram'));
  }
  html += renderGeneric(d, ['inputs', 'entities', 'correlations', 'results',
                            'ip_recon', 'instacloak', 'progress', 'summary']);
  return html;
}

/* ── Generic fallback ── */
function renderGeneric(data, skip) {
  skip = skip || [];
  var html = '';
  Object.keys(data).forEach(function (key) {
    if (skip.indexOf(key) !== -1) return;
    if (key === 'progress' || key === 'summary' || key === 'artifacts' ||
        key === 'stored_run_id' || key === 'report_dir') return;
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
      var html = '<table><thead><tr><th>Target</th><th>Type</th><th>Run ID</th><th>Time</th></tr></thead><tbody>';
      data.forEach(function (c) {
        html += '<tr><td>' + escapeHtml(c.target) + '</td><td>' + escapeHtml(c.qtype) + '</td><td>' + c.id + '</td><td>' + escapeHtml(c.run_at) + '</td></tr>';
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
      if (kind === 'diff') out.innerHTML = renderCaseDiff(data);
      else if (kind === 'timeline') out.innerHTML = renderCaseTimeline(data);
      else out.innerHTML = renderCaseProfile(data);
    })
    .catch(function (err) {
      out.innerHTML = '<p class="dim">Could not load ' + kind + '.</p>';
      showToast('Error: ' + err.message, 'error');
    });
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

function renderCaseDiff(d) {
  if (!d) return '<p class="dim">No data.</p>';
  var html = '<h3>Entity diff — ' + escapeHtml(d.target || '') +
             (d.qtype ? ' (' + escapeHtml(d.qtype) + ')' : '') + '</h3>';
  if (d.error) {
    return html + '<p class="res-line">' + escapeHtml(d.error) + '</p>';
  }
  html += '<p class="res-line">Comparing <span class="status-ok">' +
          escapeHtml(d.old_run || '?') + '</span> → <span class="status-ok">' +
          escapeHtml(d.new_run || '?') + '</span></p>';
  html += entityList('Added', d.added, 'status-ok');
  html += entityList('Removed', d.removed, 'status-err');
  return html;
}

function renderCaseTimeline(d) {
  var runs = (d && d.runs) || [];
  if (!runs.length) return '<p class="dim">No stored runs for this target.</p>';
  var html = '<h3>Timeline — ' + escapeHtml(d.target || '') +
             ' (' + runs.length + ' run' + (runs.length === 1 ? '' : 's') + ')</h3>';
  html += '<table class="res-table"><thead><tr><th>Run</th><th>Type</th><th>Entities</th></tr></thead><tbody>';
  runs.slice().reverse().forEach(function (run) {
    var ents = run.entities || [];
    html += '<tr><td>' + escapeHtml(run.run_at) + '</td><td>' + escapeHtml(run.qtype) +
            '</td><td>' + ents.length + '</td></tr>';
  });
  html += '</tbody></table>';
  return html;
}

function renderCaseProfile(d) {
  if (!d) return '<p class="dim">No data.</p>';
  var html = '<h3>Dossier — ' + escapeHtml(d.target || '') + '</h3>';
  html += '<p class="res-line">Generated <span class="status-ok">' +
          escapeHtml(d.generated || '') + '</span> · schema v' +
          escapeHtml(String(d.schema_version === undefined ? '' : d.schema_version)) +
          ' · engine ' + escapeHtml(d.spyglass_version || '') + '</p>';
  var results = d.results || {};
  var types = Object.keys(results);
  html += '<p class="res-line">Query types stored: <span class="status-ok">' +
          (types.length ? escapeHtml(types.join(', ')) : 'none') + '</span></p>';
  var entities = d.entities || {};
  Object.keys(entities).forEach(function (kind) {
    html += entityList(kind, entities[kind]);
  });
  if (!Object.keys(entities).length) {
    html += '<p class="dim">No entities extracted for this target.</p>';
  }
  return html;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
