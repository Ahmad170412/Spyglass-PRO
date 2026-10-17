/* Tests for the dashboard's pure render functions.
 *
 * These are the string builders behind the results panels, and they are
 * where misleading output hides: "no runs for this target" and "no runs
 * *because a filter is narrowing the search*" rendered identically, which
 * made a working timeline look broken.
 *
 * Run: node tests/test_frontend.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const APP_JS = path.join(__dirname, '..', 'spyglass_pro', 'static', 'js', 'app.js');

/* app.js touches the DOM at load time (token bootstrap + DOMContentLoaded
 * wiring), so hand it just enough of a browser to evaluate. */
const sandbox = {
  window: { location: { search: '', pathname: '/' }, prompt: () => null },
  document: {
    addEventListener: () => {},
    querySelectorAll: () => [],
    getElementById: () => null,
    querySelector: () => null,
  },
  localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  fetch: () => Promise.reject(new Error('not used in these tests')),
  URL,
  console,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP_JS, 'utf8'), sandbox, { filename: 'app.js' });

const { escapeHtml, emptyCases, renderCaseDiff, renderCaseTimeline, renderCaseProfile } = sandbox;

let pass = 0;
let fail = 0;

function check(name, condition, detail) {
  if (condition) {
    pass += 1;
    console.log('  [PASS] ' + name);
  } else {
    fail += 1;
    console.log('  [FAIL] ' + name + (detail ? ' — ' + detail : ''));
  }
}

console.log('== empty states name the filter ==');

const filtered = emptyCases({ target: 'a@b.com' }, 'website', 'timeline');
check('filtered empty state names the query type', filtered.includes('website'), filtered);
check('filtered empty state names the target', filtered.includes('a@b.com'), filtered);
check('filtered empty state offers a reset', filtered.includes('casesResetQtype'), filtered);

const unfiltered = emptyCases({ target: 'a@b.com' }, '', 'timeline');
check('unfiltered empty state omits the filter hint',
      !unfiltered.includes('casesResetQtype'), unfiltered);

console.log('== timeline ==');

const timeline = renderCaseTimeline(
  { target: 'a@b.com', runs: [
    { run_at: '2026-10-01T00:00:00', qtype: 'email', entities: ['domain:x.com'] },
    { run_at: '2026-10-03T00:00:00', qtype: 'email', entities: [] },
  ] }, 'email');
check('counts runs', timeline.includes('(2 runs)'), timeline);
check('newest first', timeline.indexOf('2026-10-03') < timeline.indexOf('2026-10-01'), timeline);

check('no runs falls back to the diagnostic empty state',
      renderCaseTimeline({ target: 'a@b.com', runs: [] }, 'website').includes('website'));
check('missing runs key does not throw',
      renderCaseTimeline({ target: 'a@b.com' }, '').includes('a@b.com'));

console.log('== diff ==');

const noPair = renderCaseDiff(
  { target: 'a@b.com', qtype: null, added: [], removed: [],
    error: 'need at least two stored runs to diff' }, '');
check('needs-two-runs explains itself without a filter',
      noPair.includes('No comparable stored runs'), noPair);

const filteredPair = renderCaseDiff(
  { target: 'a@b.com', qtype: null, added: [], removed: [],
    error: 'need at least two stored runs to diff' }, 'email');
check('needs-two-runs with a filter offers the reset',
      filteredPair.includes('casesResetQtype'), filteredPair);

const realDiff = renderCaseDiff(
  { target: 'a@b.com', qtype: 'email', old_run: 'T1', new_run: 'T2',
    added: ['domain:new.com'], removed: [] }, 'email');
check('renders added entities', realDiff.includes('domain:new.com'), realDiff);
check('renders both run stamps', realDiff.includes('T1') && realDiff.includes('T2'), realDiff);

console.log('== profile ==');

check('empty profile under a filter explains itself',
      renderCaseProfile({ target: 'a@b.com', results: {} }, 'ip').includes('casesResetQtype'));

console.log('== escaping ==');

const injected = renderCaseTimeline({
  target: '<img src=x onerror=alert(1)>',
  runs: [{ run_at: 'now', qtype: 'email', entities: [] }],
}, '');
check('target is escaped, not injected', !injected.includes('<img'), injected);

const entityInjection = sandbox.entityList('Added', ['<script>alert(1)</script>']);
check('entity values are escaped', !entityInjection.includes('<script'), entityInjection);

check('escapeHtml handles quotes', escapeHtml('a"b') === 'a&quot;b');

console.log('== partial-recon notice ==');

/* The topbar pills are gone, but the Overview banner must still render:
   updateEngineTags once returned early without them and the banner died
   silently. Stub only getElementById; everything else stays as-is. */
(function () {
  const realGet = sandbox.document.getElementById;
  const notice = { innerHTML: '', style: {} };
  sandbox.document.getElementById = (id) => (id === 'toolNotice' ? notice : null);
  try {
    sandbox.updateEngineTags({ degraded: { email: ['holehe'] }, tools: {}, platforms: [], engines: {} });
    check('notice names the missing tool without the pills', notice.innerHTML.includes('holehe'), notice.innerHTML);
    check('notice becomes visible', notice.style.display === 'block', notice.style.display);
    sandbox.updateEngineTags({ degraded: {}, tools: {}, platforms: [], engines: {} });
    check('notice hides when nothing is missing', notice.style.display === 'none', notice.style.display);
  } finally {
    sandbox.document.getElementById = realGet;
  }
})();

console.log('== normalized facts block ==');

const normBlock = {
  engine: 'spyglass_osint',
  facts: [
    { key: 'accounts_total', label: 'Accounts found', value: 2, source: 'spyglass_osint', confidence: 'high' },
    { key: 'accounts_single', label: 'Accounts (single engine)', value: 1, source: 'spyglass_osint', confidence: 'medium' },
    { key: 'proxy_configured', label: 'Proxy configured', value: false, source: 'self-check', confidence: 'high' },
  ],
  entities: [
    { kind: 'email', value: 'a@x.com', source: 'target' },
    { kind: 'domain', value: 'x.com', source: 'spyglass_osint' },
  ],
};
const normHtml = sandbox.renderNormalized(normBlock);
check('facts render with labels', normHtml.includes('Accounts found') && normHtml.includes('2'), normHtml);
check('medium confidence is badged, not hidden', normHtml.includes('medium'), normHtml);
check('false bool renders as no, not blank', normHtml.includes('>no<') || normHtml.includes('>no '), normHtml);
check('entities grouped by kind', normHtml.includes('email (1)') && normHtml.includes('x.com'), normHtml);
check('source shown per fact', normHtml.includes('spyglass_osint'), normHtml);
check('absent block renders nothing', sandbox.renderNormalized(null) === '', 'null block');
check('empty block renders nothing', sandbox.renderNormalized({ facts: [], entities: [] }) === '', 'empty block');
check('injection in fact value is escaped',
      !sandbox.renderNormalized({ facts: [{ key: 'x', label: 'X', value: '<script>alert(1)</script>', source: 's', confidence: 'high' }], entities: [] }).includes('<script>'));

console.log('== timeline entity chips ==');
const tlChips = renderCaseTimeline(
  { target: 'a@b.com', runs: [{ run_at: '2026-10-03', qtype: 'email', entities: ['email:a@b.com', 'domain:x.com'] }] }, '');
check('timeline shows entity values inline', tlChips.includes('domain:x.com'), tlChips);

console.log('== dossier actions ==');
const dossierHtml = renderCaseProfile(
  { target: 'a@b.com', generated: 'now', schema_version: 1, spyglass_version: 'x',
    entities: { emails: ['a@b.com'] }, results: { email: { ok: 1 } } }, '');
check('dossier offers copy', dossierHtml.includes('dossierCopy'), dossierHtml);
check('dossier offers download', dossierHtml.includes('dossierDl'), dossierHtml);

console.log('== results wire up the facts block ==');
(function () {
  const realGet = sandbox.document.getElementById;
  const boxes = {};
  sandbox.document.getElementById = (id) => {
    if (id === 'toolNotice') return { innerHTML: '', style: {} };
    if (String(id).indexOf('scanning-') === 0) return null;
    if (!boxes[id]) boxes[id] = { innerHTML: '', insertAdjacentHTML(pos, html) { this.innerHTML += html; } };
    return boxes[id];
  };
  try {
    const withNorm = { summary: 'Email recon for a@b.com', foo: 'bar',
      normalized: { engine: 'spyglass_osint',
        facts: [{ key: 'a', label: 'Accounts found', value: 2, source: 's', confidence: 'high' }],
        entities: [{ kind: 'email', value: 'a@b.com', source: 'target' }] } };
    sandbox.displayResults('boxA', withNorm, false, 'email');
    check('displayResults renders Key findings when normalized is present',
      boxes.boxA.innerHTML.includes('Key findings'), boxes.boxA.innerHTML.slice(0, 200));
    const withoutNorm = { summary: 'Email recon for a@b.com', foo: 'bar' };
    sandbox.displayResults('boxB', withoutNorm, false, 'email');
    check('displayResults renders no Key findings without a block',
      !boxes.boxB.innerHTML.includes('Key findings'), boxes.boxB.innerHTML.slice(0, 200));
  } finally {
    sandbox.document.getElementById = realGet;
  }
})();

console.log('== dossier filename ==');
sandbox.lastDossier = { target: '../../etc/passwd' };
check('dossier filename strips path traversal',
  !sandbox.dossierFilename().includes('/') && !sandbox.dossierFilename().includes('..'),
  sandbox.dossierFilename());
sandbox.lastDossier = { target: 'User@Example.COM' };
check('dossier filename is JSON for the target',
  sandbox.dossierFilename().endsWith('.json') && sandbox.dossierFilename().includes('user'),
  sandbox.dossierFilename());

console.log('== keyless tabs hide browser options ==');
(function () {
  const realGet = sandbox.document.getElementById;
  const labels = [{ style: {} }, { style: {} }, { style: {} }];
  const form = { querySelectorAll: (sel) => (sel === '[data-browser-only]' ? labels : []) };
  const burnerRow = { style: {} };
  const caps = { textContent: '' };
  sandbox.document.getElementById = (id) => (
    id === 'form-social' ? form : id === 'burnerRow' ? burnerRow
    : id === 'socialCaps' ? caps : null);
  try {
    const list = [
      { key: 'instagram', label: 'Instagram', login: 'instacloak', browser: true, capabilities: [] },
      { key: 'mastodon', label: 'Mastodon', login: 'none', browser: false, capabilities: [] },
      { key: 'bluesky', label: 'Bluesky', login: 'none', browser: false, capabilities: [] },
      { key: 'github', label: 'GitHub', login: 'none', browser: false, capabilities: [] },
    ];
    sandbox.showCaps(list, 'mastodon');
    check('keyless tab hides headless/deep/media',
      labels.every((l) => l.style.display === 'none'), JSON.stringify(labels.map((l) => l.style.display)));
    sandbox.showCaps(list, 'instagram');
    check('instagram tab keeps browser options',
      labels.every((l) => l.style.display === ''), JSON.stringify(labels.map((l) => l.style.display)));
    sandbox.showCaps(list, 'bluesky');
    check('keyless tab hides the burner row', burnerRow.style.display === 'none', burnerRow.style.display);
    sandbox.showCaps(list, 'github');
    check('new keyless tab behaves like the others',
      burnerRow.style.display === 'none'
      && labels.every((l) => l.style.display === 'none'), burnerRow.style.display);
    sandbox.showCaps(list, 'no-such-platform');
    check('platform unknown to the server names the gap and hides browser options',
      caps.textContent.includes('not in this server') && labels.every((l) => l.style.display === 'none'),
      caps.textContent);
    check('the gap message is a reason, not a blank', caps.textContent.length > 40, caps.textContent);
  } finally {
    sandbox.document.getElementById = realGet;
  }
})();
(function () {
  const realGet = sandbox.document.getElementById;
  const fields = {
    socialPlatform: { value: 'instagram' },
    socialPlatformName: { textContent: '' },
    socialHandle: { placeholder: '' },
    socialCaps: { textContent: '' },
    burnerRow: { style: {} },
  };
  sandbox.document.getElementById = (id) => fields[id] || null;
  const realFetch = sandbox.fetch;
  sandbox.fetch = () => Promise.reject(new Error('no network in tests'));
  try {
    sandbox.SOCIAL_LABELS = { instagram: 'Instagram', mastodon: 'Mastodon', bluesky: 'Bluesky' };
    sandbox.selectSocialPlatform('mastodon');
    check('tab sets the hidden field', fields.socialPlatform.value === 'mastodon', fields.socialPlatform.value);
    check('tab updates the name line', fields.socialPlatformName.textContent === 'Mastodon', fields.socialPlatformName.textContent);
    check('tab rewrites the placeholder', fields.socialHandle.placeholder.includes('instance'), fields.socialHandle.placeholder);
    sandbox.selectSocialPlatform('github');
    check('a click on a platform the registry has not answered for still wins the form',
      fields.socialPlatform.value === 'github'
      && fields.socialPlatformName.textContent === 'GitHub'
      && fields.socialHandle.placeholder.includes('github'),
      fields.socialPlatform.value + ' / ' + fields.socialPlatformName.textContent);
  } finally {
    sandbox.document.getElementById = realGet;
    sandbox.fetch = realFetch;
  }
})();
const registryFetchTest = (async function () {
  /* A dead registry fetch must keep the operator's platform and explain
   * itself — drive loadSocialPlatforms' catch branch directly. */
  const realGet = sandbox.document.getElementById;
  const fields = {
    socialPlatform: { value: 'github' },
    socialCaps: { textContent: '' },
  };
  sandbox.document.getElementById = (id) => fields[id] || null;
  const realFetch = sandbox.fetch;
  sandbox.fetch = () => Promise.reject(new Error('no network in tests'));
  try {
    sandbox.loadSocialPlatforms();
    await new Promise((resolve) => setTimeout(resolve, 0));
    check('a failed registry fetch explains itself with a next step',
      fields.socialCaps.textContent.includes('Could not reach the platform registry')
      && fields.socialCaps.textContent.includes('reload'),
      fields.socialCaps.textContent);
    check('a failed registry fetch keeps the operator choice',
      fields.socialPlatform.value === 'github', fields.socialPlatform.value);
  } finally {
    sandbox.document.getElementById = realGet;
    sandbox.fetch = realFetch;
  }
})();

console.log('== preflight names the upgrade ==');
(function () {
  sandbox.STATUS = { tools: { shodan: true }, degraded: {}, platforms: [], engines: {} };
  sandbox.SETTINGS_CACHE = { keys: [
    { key: 'shodan_api_key', configured: false },
    { key: 'virustotal_api_key', configured: true },
    { key: 'abuseipdb_api_key', configured: false },
  ] };
  const pf = sandbox.preflightHtml('ip');
  check('names the missing keys', pf.includes('Shodan') && pf.includes('AbuseIPDB'), pf);
  check('names what each key unlocks', pf.includes('open ports') && pf.includes('abuse confidence'), pf);
  check('stays partial', pf.includes('PARTIAL POWER'), pf);
  sandbox.SETTINGS_CACHE = { keys: [
    { key: 'shodan_api_key', configured: true },
    { key: 'virustotal_api_key', configured: true },
    { key: 'abuseipdb_api_key', configured: true },
  ] };
  const fullKeys = sandbox.preflightHtml('ip');
  check('no upgrade hint when nothing is missing', !fullKeys.includes('add Shodan'), fullKeys);
  sandbox.SETTINGS_CACHE = null;
  const unknown = sandbox.preflightHtml('ip');
  check('unknown vault guesses nothing', !unknown.includes('add Shodan') && unknown.includes('Settings'), unknown);
  sandbox.STATUS = null;
  sandbox.SETTINGS_CACHE = null;
})();

console.log('== investigation: verdict first, links lit ==');
(function () {
  const inv = sandbox.renderInvestigate({
    inputs: { email: 'a@b.com' },
    entities: { emails: ['a@b.com'], domains: ['x.com', 'other.com'] },
    correlations: [
      { type: 'info', desc: 'Org appears in WHOIS and breach data', detail: 'Acme' },
      { type: 'match', desc: 'Email domain matches website target', detail: 'x.com' },
    ],
    results: {},
  });
  check('matches sort above info', inv.indexOf('corr-match') < inv.indexOf('Org appears'), inv.slice(0, 300));
  check('heading counts matches', inv.includes('Correlations (2, 1 match)'), inv.slice(0, 200));
  check('matched entity lights up', inv.includes('chip-match'), inv.slice(0, 500));
  check('unmatched entity stays plain', inv.includes('<span class="chip">other.com</span>'), inv.slice(0, 800));
  check('graph draws kinds with real counts',
    inv.includes('<svg') && inv.includes('domains · 2') && inv.includes('a@b.com'), inv.slice(0, 300));
  const single = sandbox.renderInvestigate({ entities: { emails: ['a@b.com'] }, correlations: [] });
  check('single kind needs no graph', !single.includes('<svg'), single.slice(0, 200));
  const injected = sandbox.renderInvestigate({
    entities: { emails: ['<img src=x onerror=alert(1)>'] }, correlations: [],
  });
  check('graph and chips escape input', !injected.includes('<img'), injected.slice(0, 300));
})();

console.log('== social preflight tells the truth ==');
(function () {
  const realGet = sandbox.document.getElementById;
  sandbox.document.getElementById = (id) => (id === 'toolNotice' ? { innerHTML: '', style: {} } : null);
  try {
    sandbox.STATUS = { tools: {}, degraded: {}, platforms: [{}, {}, {}], engines: {} };
    const pf = sandbox.preflightHtml('social');
    check('names the registry, not 0/0 tools',
      pf.includes('keyless Mastodon/Bluesky') && !pf.includes('0/0'), pf);
    check('full power when loaded', pf.includes('FULL POWER'), pf);
    sandbox.STATUS = { tools: {}, degraded: {}, platforms: [], engines: {} };
    const dead = sandbox.preflightHtml('social');
    check('dead engine reads as failure, not full power',
      dead.includes('PARTIAL POWER') && dead.includes('failed to load'), dead);
  } finally {
    sandbox.document.getElementById = realGet;
    sandbox.STATUS = null;
  }
})();

console.log('== social session honesty ==');
(function () {
  sandbox.SOCIAL_META = { mastodon: { browser: false }, instagram: { browser: true } };
  const keyless = sandbox.renderSocial({ platform: 'mastodon', handle: 'u' });
  check('keyless shows no-session line, not red logged-out',
    keyless.includes('none needed (keyless)') && !keyless.includes('logged out'), keyless.slice(0, 300));
  const insta = sandbox.renderSocial({ platform: 'instagram', handle: 'u' });
  check('instagram keeps logged-out', insta.includes('logged out'), insta.slice(0, 200));
  const burner = sandbox.renderSocial({ platform: 'instagram', handle: 'u', logged_in: true });
  check('burner login shown', burner.includes('burner logged in'), burner.slice(0, 200));
})();

console.log('== social plurals and dates ==');
(function () {
  check('1 like / 2 likes',
    sandbox.pluralize(1, 'like') === '1 like' && sandbox.pluralize(2, 'like') === '2 likes'
    && sandbox.pluralize(0, 'comment') === '0 comments');
  const posts = sandbox.renderSocial({ platform: 'mastodon', handle: 'u',
    posts: [{ caption: 'hi', likes: 1, comments: 2, timestamp: '2024-05-01T10:00:00.000Z', url: '' }] });
  check('post meta pluralizes with date',
    posts.includes('1 like') && posts.includes('2 comments') && posts.includes('2024-05-01'), posts.slice(0, 400));
  const joined = sandbox.renderSocial({ platform: 'mastodon', handle: 'u', joined: '2016-03-16T00:00:00.000Z' });
  check('joined sliced to date', joined.includes('2016-03-16') && !joined.includes('00:00:00'), joined.slice(0, 300));
})();

console.log('== run timestamps read uniformly ==');
check('lens microseconds trimmed',
  sandbox.fmtRunAt('2026-10-03T12:14:52.896458+00:00') === '2026-10-03T12:14:52');
check('spyglass stamps untouched', sandbox.fmtRunAt('2026-10-03T15:52:04') === '2026-10-03T15:52:04');
check('missing stamp is blank', sandbox.fmtRunAt(null) === '');

/* The registry-failure test above is asynchronous; let its checks land
 * before the tally prints, so the summary matches what actually ran. */
Promise.resolve(registryFetchTest).then(function () {
  console.log(`\n${'='.repeat(40)}\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
});