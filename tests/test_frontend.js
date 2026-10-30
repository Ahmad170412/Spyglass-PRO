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

const { escapeHtml, emptyCases, renderCaseDiff, renderCaseTimeline, renderCaseProfile,
        confirmAction, deleteCase, caseRowHtml } = sandbox;

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

console.log('== case deletion uses the themed dialog ==');

check('deleteCase no longer calls window.confirm',
      !deleteCase.toString().includes('window.confirm'), deleteCase.toString());
check('deleteCase routes through confirmAction',
      deleteCase.toString().includes('confirmAction'), deleteCase.toString());
check('confirmAction drives the themed dialog',
      confirmAction.toString().includes('confirmDialog') &&
      confirmAction.toString().includes('showModal'), confirmAction.toString());

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

console.log('== social fields diff ==');

/* A changed link must be verifiable by clicking: the full href rides
   behind a short host + path label. A truncated display string ending in
   "…" is not a URL and gets rejected wherever it is pasted. */
const socialFieldsVerdict = {
  ok: true, changed: true,
  counts: [], posts: { added: [], added_count: 0, compared: 0 },
  fields: [
    { key: 'avatar_url', label: 'Avatar',
      old: 'https://cdn.example/u/1/old.jpg?oh=aaa&oe=111',
      new: 'https://cdn.example/u/1/new.jpg?oh=bbb&oe=222' },
    { key: 'bio', label: 'Bio', old: 'first bio', new: 'second bio' },
  ],
  walls: { new: [], resolved: [] },
  lists: {},
};
const socialHistory = [
  { taken_at: '2026-10-29T22:42:00', payload: {} },
  { taken_at: '2026-10-29T22:22:00', payload: {} },
];
const fieldsHtml = sandbox.dashDiffHtml(
  socialFieldsVerdict, { handle: 'qrxznat' }, socialHistory);
check('field change renders its label and tag',
      fieldsHtml.includes('Avatar') && fieldsHtml.includes('changed'), fieldsHtml);
check('link change carries the full href for verification',
      fieldsHtml.includes('href="https://cdn.example/u/1/old.jpg?oh=aaa&amp;oe=111"'), fieldsHtml);
check('link display stays a short host + path label',
      fieldsHtml.includes('cdn.example/u/1/new.jpg?…'), fieldsHtml);
check('non-link values render as plain text with an arrow',
      fieldsHtml.includes('first bio') && fieldsHtml.includes('second bio'), fieldsHtml);
check('non-http(s) values never become links',
      !sandbox.linkValHtml('javascript:alert(1)').includes('<a '),
      sandbox.linkValHtml('javascript:alert(1)'));

/* A refused phase must show its reason — "could not compare" rendering
   as "nothing changed" is how a UI starts lying. */
const refusedVerdict = {
  ok: true, changed: false,
  counts: [{ key: 'follower_count', label: 'Followers', old: 100, new: 100, delta: 0 }],
  posts: { added: [], added_count: 0, compared: 0,
    refused: 'the previous check retrieved no posts and it reported 4,185 posts — additions cannot be claimed' },
  fields: [], walls: { new: [], resolved: [] }, lists: {},
};
const refusedHtml = sandbox.dashDiffHtml(
  refusedVerdict, { handle: 'jay.bsky.team' }, socialHistory);
check('refused posts phase renders its reason',
      refusedHtml.includes('additions cannot be claimed'), refusedHtml);
check('refusal does not read as "nothing changed"',
      !refusedHtml.includes('No changes since the previous check'), refusedHtml);

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
      { key: 'gitlab', label: 'GitLab', login: 'none', browser: false, capabilities: [] },
      { key: 'keybase', label: 'Keybase', login: 'none', browser: false, capabilities: [] },
    ];
    sandbox.showCaps(list, 'mastodon');
    check('keyless tab hides headless/deep/media',
      labels.every((l) => l.style.display === 'none'), JSON.stringify(labels.map((l) => l.style.display)));
    sandbox.showCaps(list, 'instagram');
    check('instagram tab keeps browser options',
      labels.every((l) => l.style.display === ''), JSON.stringify(labels.map((l) => l.style.display)));
    sandbox.showCaps(list, 'bluesky');
    /* The burner moved to Settings (account config, not target config):
       the social form has no burner row, so showCaps must leave any
       stale reference untouched rather than toggle a ghost control. */
    check('the burner row is gone: showCaps leaves it alone',
      burnerRow.style.display === undefined, String(burnerRow.style.display));
    sandbox.showCaps(list, 'github');
    check('new keyless tab behaves like the others',
      labels.every((l) => l.style.display === 'none')
      && caps.textContent.includes('keyless'), caps.textContent);
    sandbox.showCaps(list, 'gitlab');
    check('gitlab behaves like every other keyless tab',
      labels.every((l) => l.style.display === 'none')
      && !caps.textContent.includes('not in this server'), caps.textContent);
    sandbox.showCaps(list, 'keybase');
    check('keybase behaves like every other keyless tab',
      labels.every((l) => l.style.display === 'none')
      && !caps.textContent.includes('not in this server'), caps.textContent);
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
    sandbox.selectSocialPlatform('gitlab');
    check('gitlab click wins the form without a registry answer',
      fields.socialPlatform.value === 'gitlab'
      && fields.socialPlatformName.textContent === 'GitLab'
      && fields.socialHandle.placeholder.includes('gitlab'),
      fields.socialPlatform.value + ' / ' + fields.socialPlatformName.textContent);
    sandbox.selectSocialPlatform('keybase');
    check('keybase click wins the form without a registry answer',
      fields.socialPlatform.value === 'keybase'
      && fields.socialPlatformName.textContent === 'Keybase'
      && fields.socialHandle.placeholder.includes('keybase'),
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
  sandbox.STATUS = { tools: { dig: true, whois: true }, degraded: {}, platforms: [], engines: {} };
  sandbox.SETTINGS_CACHE = { keys: [
    { key: 'intelx_api_key', configured: false },
    { key: 'hibp_api_key', configured: true },
  ] };
  const pf = sandbox.preflightHtml('darkweb');
  check('names the missing keys', pf.includes('IntelX'), pf);
  check('names what each key unlocks', pf.includes('paste + breach archive'), pf);
  check('stays partial', pf.includes('PARTIAL POWER'), pf);
  sandbox.SETTINGS_CACHE = { keys: [
    { key: 'intelx_api_key', configured: true },
    { key: 'hibp_api_key', configured: true },
  ] };
  const fullKeys = sandbox.preflightHtml('darkweb');
  check('no upgrade hint when nothing is missing', !fullKeys.includes('add IntelX'), fullKeys);
  sandbox.SETTINGS_CACHE = null;
  const unknown = sandbox.preflightHtml('darkweb');
  check('unknown vault guesses nothing', !unknown.includes('add IntelX') && unknown.includes('Settings'), unknown);
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

console.log('== person card: identity first, engines and context visible ==');
(function () {
  const person = {
    confidence: 'high',
    counts: { anchors: 2, accounts: 1, confirmed_links: 1, possible_links: 1,
              conflicts: 1, breaches: 1 },
    anchors: [{ kind: 'email', value: 'analyst@example.com', source: 'input' },
              { kind: 'username', value: 'analyst', source: 'input' }],
    names: [{ value: 'Analyst', source: 'instagram', confidence: 'high' }],
    handles: [{ value: 'analyst', source: 'input', confidence: 'high' }],
    emails: [{ value: 'analyst@example.com', source: 'input', confidence: 'high' }],
    phones: [], locations: [], organizations: [],
    domains: [{ value: 'example.com', source: 'input website',
                confidence: 'medium', context: true }],
    websites: [],
    accounts: [{ platform: 'github.com', url: 'https://github.com/analyst',
                 via: ['email', 'username'], tools: ['holehe', 'user-scanner'],
                 confidence: 'high' }],
    breaches: [{ name: 'LeakDB', date: '2021', via: ['email'] }],
    exposed_fields: ['email'],
    links: [
      { kind: 'whois-email', desc: 'Known email found in website WHOIS',
        detail: 'analyst@example.com', confidence: 'high' },
      { kind: 'handle-reuse',
        desc: 'Handle @analyst appears on 3 platforms — same handle, not proof of one person',
        detail: 'github.com, mastodon.social', confidence: 'possible' },
    ],
    conflicts: [{ kind: 'location',
                  desc: 'Profile location "Berlin" differs from WHOIS country "Russia"',
                  values: ['Berlin', 'Russia'] }],
    context: { website: 'example.com', organizations: ['Acme Ltd'],
               emails: ['legal@example.com'] },
    notes: ['WHOIS values describe the domain, not necessarily the person.'],
  };
  const data = {
    inputs: { email: 'analyst@example.com', username: 'analyst' },
    entities: { emails: ['analyst@example.com'], domains: ['github.com'] },
    correlations: [{ type: 'match', desc: 'Email domain matches website target',
                     detail: 'example.com' }],
    results: { email: { both: [{ domain: 'github.com', url: 'https://github.com/analyst',
                                 engines: ['holehe', 'user-scanner'] }] } },
    social: { platform: 'instagram', handle: 'analyst', found: true,
              display_name: 'Analyst', source: 'browser', logged_in: false },
    person: person,
  };
  const card = sandbox.renderResult(data, 'investigate');
  check('renders identity and source', card.body.includes('Identity') &&
        card.body.includes('analyst@example.com'), card.body.slice(0, 400));
  check('identity is the compact grid, not a tall table',
        card.body.includes('person-identity-grid') &&
        !card.body.includes('person-meta'), card.body.slice(0, 600));
  check('accounts show every engine', card.body.includes('github.com') &&
        card.body.includes('holehe') && card.body.includes('user-scanner'),
        card.body.slice(0, 600));
  check('accounts fold URL and evidence into one column',
        card.body.includes('<th>Account</th>') &&
        card.body.includes('<th>Found by</th>') &&
        !card.body.includes('<th>Evidence</th>') &&
        !card.body.includes('<th>URL</th>'), card.body.slice(0, 700));
  check('links are rows, not nested cards',
        card.body.includes('person-link-body') &&
        !card.body.includes('person-link-high'), card.body.slice(0, 900));
  check('possible lead is labelled', card.body.includes('possible') &&
        card.body.includes('not proof of one person'), card.body.slice(0, 800));
  check('conflict is surfaced', card.body.includes('Conflicts (1)') &&
        card.body.includes('differs from WHOIS'), card.body.slice(0, 800));
  check('domain context stays separate and captioned',
        card.body.includes('Domain context') &&
        card.body.includes('not necessarily the person') &&
        card.body.includes('legal@example.com'), card.body.slice(0, 900));
  check('raw module payloads stay off the face',
        !card.body.includes('user-scanner_only') && !card.body.includes('Only holehe'),
        card.body.slice(0, 900));
  check('raw modules live in Details', card.details.includes('email') &&
        card.details.includes('github.com'), card.details.slice(0, 400));
  check('details entity index is a compact grid, not a second graph',
        card.details.includes('person-identity-grid') &&
        !card.details.includes('entity-graph'), card.details.slice(0, 500));
  check('identity notes live in Details',
        card.details.includes('WHOIS values describe the domain'), card.details.slice(0, 400));

  const injected = sandbox.renderResult({
    person: Object.assign({}, person, {
      names: [{ value: '<img src=x onerror=alert(1)>', source: 'x' }],
    }),
  }, 'investigate');
  check('person fields are escaped', !injected.body.includes('<img'),
        injected.body.slice(0, 300));

  const legacy = sandbox.renderResult(
    { entities: { emails: ['a@b.com'] }, correlations: [] }, 'investigate');
  check('legacy run keeps the entities-first layout',
        legacy.body.includes('Entities') && legacy.details === '',
        legacy.body.slice(0, 300));
})();

console.log('== social preflight tells the truth ==');
(function () {
  const realGet = sandbox.document.getElementById;
  sandbox.document.getElementById = (id) => (id === 'toolNotice' ? { innerHTML: '', style: {} } : null);
  try {
    sandbox.STATUS = { tools: {}, degraded: {}, platforms: [{}, {}, {}], engines: {} };
    const pf = sandbox.preflightHtml('social');
    check('a healthy social scan is badge-only, not a platform roll-call',
      !pf.includes('keyless Mastodon') && !pf.includes('0/0')
      && !pf.includes('preflight-detail'), pf);
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
  const keyless = sandbox.renderSocialDetails({ platform: 'mastodon', handle: 'u' });
  check('keyless shows no-session line, not red logged-out',
    keyless.includes('none needed (keyless)') && !keyless.includes('logged out'), keyless.slice(0, 300));
  const insta = sandbox.renderSocialDetails({ platform: 'instagram', handle: 'u' });
  check('instagram keeps logged-out', insta.includes('logged out'), insta.slice(0, 200));
  const burner = sandbox.renderSocialDetails({ platform: 'instagram', handle: 'u', logged_in: true });
  check('burner login shown', burner.includes('burner logged in'), burner.slice(0, 200));
  const body = sandbox.renderSocial({ platform: 'instagram', handle: 'u', source: 'browser' });
  check('session chatter stays out of the profile body',
    !body.includes('logged out') && !body.includes('Session') && !body.includes('Source'),
    body.slice(0, 300));
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

console.log('== website: light renderer ==');
(function () {
  const w = sandbox.renderWebsite({
    whois: { Registrar: 'Example Registrar' },
    dns_records: { A: '1.2.3.4' },
    ct: ['www.example.com'],
    // Removed infra keys must not render even if a legacy payload has them.
    subdomains: ['should-not-render.example.com'],
    shodan: { ports: [80] },
    title: 'nope',
    status_code: 200,
  });
  check('renders owner / DNS / CT',
    w.includes('WHOIS') && w.includes('DNS records') && w.includes('Certificate transparency'),
    w.slice(0, 300));
  check('does not render removed infra keys',
    !w.includes('Shodan') && !w.includes('Subdomains') && !w.includes('Page title'),
    w.slice(0, 300));
  const entry = sandbox.RENDERERS.find(function (r) { return r.name === 'website'; });
  check('website matcher fires on light keys',
    !!entry && entry.matches({ whois: {} }) && entry.matches({ dns_records: {} })
    && entry.matches({ ct: ['x'] }));
  check('website no longer matches on subdomains',
    !!entry && !entry.matches({ subdomains: ['x'] }));
})();

console.log('== results first, machinery in the drawers ==');
(function () {
  const e = sandbox.renderEmail({
    both: [{ domain: 'instagram.com', url: 'https://instagram.com',
             engines: ['holehe', 'user-scanner'] },
           { domain: 'spotify.com' }],
    holehe_only: [{ domain: 'pinterest.com', engines: ['holehe'] }],
    user_scanner_only: [{ domain: 'github.com', url: 'https://github.com' }],
    blackbird_only: [],
    breach: { found: 2 },
  });
  check('email: one accounts table with a Found by column',
    e.includes('<th>Found by</th>') && e.includes('instagram.com')
    && e.includes('holehe + user-scanner'), e.slice(0, 700));
  check('email: bucket label is the fallback when engines are absent',
    e.includes('2+ engines') && e.includes('user-scanner'), e.slice(0, 700));
  check('email: per-engine bucket headings are gone',
    !e.includes('user-scanner only') && !e.includes('Found by multiple engines'),
    e.slice(0, 700));

  const u = sandbox.renderUsername({
    all_4: [{ domain: 'a.com', url: 'https://a.com' }],
    us_only: [{ domain: 'b.com' }],
  });
  check('username: names every engine that agreed',
    u.includes('user-scanner + sherlock + maigret + blackbird') && u.includes('Found by'),
    u.slice(0, 700));

  const w = sandbox.renderWebsite({
    whois: { Registrar: 'R' }, dns_records: { A: '1.2.3.4' },
    ct: ['www.example.com'],
  });
  check('website: each result block names its tool',
    w.includes('result-tool') && w.includes('whois') && w.includes('dig') && w.includes('crt.sh'),
    w.slice(0, 900));

  const sec = sandbox.renderSection('DNS records', 'x', 'dig');
  check('renderSection carries a tool pill', sec.includes('result-tool') && sec.includes('dig'), sec);

  const tab = sandbox.resultTab('Run log', 'x', 3);
  check('drawer starts collapsed and counts its lines',
    tab.indexOf('<details class="result-tab">') === 0 && tab.includes('Run log (3)')
    && !tab.includes(' open'), tab);

  const head = sandbox.resultHead({}, 'email', 'a@b.com');
  check('card head names the kind and target',
    head.includes('>Email<') && head.includes('a@b.com'), head);

  const split = sandbox.renderResult(
    { platform: 'mastodon', handle: 'u', source: 'http', metrics: { posts: 2 } }, 'social');
  check('social diagnostics split out of the body',
    split.body.includes('No profile fields retrieved') && !split.body.includes('Source')
    && split.details.includes('Source') && split.details.includes('Collected'),
    split.body.slice(0, 300) + ' || ' + split.details.slice(0, 300));
})();

console.log('== run timestamps read uniformly ==');
check('lens microseconds trimmed',
  sandbox.fmtRunAt('2026-10-03T12:14:52.896458+00:00') === '2026-10-03T12:14:52');
check('spyglass stamps untouched', sandbox.fmtRunAt('2026-10-03T15:52:04') === '2026-10-03T15:52:04');
check('missing stamp is blank', sandbox.fmtRunAt(null) === '');

console.log('== legacy lens cases are listed but not loadable ==');
const lensRow = caseRowHtml({ id: 3, target: '1.1.1.1', qtype: 'lens_passive',
                               run_at: '2026-10-03T12:14:52.896458+00:00' });
check('lens row is marked legacy', lensRow.includes('data-legacy="1"')
  && lensRow.includes('case-row-legacy'), lensRow);
check('lens row says its history is unavailable',
  lensRow.includes('not available in this build'), lensRow);
check('lens row can still be deleted', lensRow.includes('data-del-id="3"')
  && lensRow.includes('data-del-qtype="lens_passive"'), lensRow);
const spyglassRow = caseRowHtml({ id: 4, target: 'a@b.com', qtype: 'email',
                                  run_at: '2026-10-03T15:52:04' });
check('a normal case row stays loadable', !spyglassRow.includes('data-legacy')
  && !spyglassRow.includes('case-row-legacy'), spyglassRow);
check('a normal case row still offers its timeline',
  spyglassRow.includes('Load this target'), spyglassRow);

/* ── Targets + CHECK AGAIN: the tracked-target flow's renderers ──
 * These are pure string builders over server shapes: target rows, stat
 * deltas, the diff verdict (refusals included) and the history rail.
 * The async part proves a dead store resolves into a blank state rather
 * than an unhandled rejection. */
const targetFlowTest = (async function () {
  console.log('== Targets + CHECK AGAIN module ==');

  check('the tracked-target flow is present',
    typeof sandbox.loadSocialDashboard === 'function'
    && typeof sandbox.checkTarget === 'function'
    && typeof sandbox.loadTargets === 'function'
    && typeof sandbox.addTargetFromForm === 'function'
    && typeof sandbox.removeTargetFlow === 'function', '');
  check('a check only exists against a tracked target',
    sandbox.checkTarget.toString().includes('/api/social/targets/')
    && sandbox.checkTarget.toString().includes('No tracked target'),
    sandbox.checkTarget.toString().slice(0, 200));

  check('timestamps read as day · time',
    sandbox.fmtWhen('2026-10-28T08:29:00') === '28 Oct · 08:29',
    sandbox.fmtWhen('2026-10-28T08:29:00'));
  check('a missing timestamp is blank, not Invalid Date',
    sandbox.fmtWhen('') === '' && sandbox.fmtWhen(null) === '',
    JSON.stringify([sandbox.fmtWhen(''), sandbox.fmtWhen(null)]));

  console.log('== target rows ==');
  const unchecked = sandbox.targetRowHtml(
    { id: 7, platform: 'bluesky', handle: 'dawn.example.bsky.social',
      checks: 0, baseline_at: null, last_check_at: null, last_status: null });
  check('an unchecked target says no checks yet',
    unchecked.includes('no checks yet'), unchecked);
  check('a row can start a check and forget the target',
    unchecked.includes('data-check-id="7"') && unchecked.includes('data-del-id="7"'),
    unchecked);
  const checked = sandbox.targetRowHtml(
    { id: 8, platform: 'github', handle: 'ahmad-dev', checks: 3,
      baseline_at: '2026-10-20T17:02:00', last_check_at: '2026-10-28T08:33:00',
      last_status: 'ok' });
  check('a checked target shows count and baseline',
    checked.includes('3 checks') && checked.includes('baseline 20 Oct · 17:02'),
    checked);
  const failed = sandbox.targetRowHtml(
    { id: 9, platform: 'mastodon', handle: 'dawn', checks: 2,
      baseline_at: '2026-10-27T11:30:00', last_check_at: '2026-10-28T08:31:00',
      last_status: 'instance refused the list this time' });
  check('a failed last check is visible on the row',
    failed.includes('last check failed'), failed);
  const hostileRow = sandbox.targetRowHtml(
    { id: 10, platform: 'mastodon', handle: '<img src=x onerror=alert(1)>',
      checks: 0, baseline_at: null, last_check_at: null, last_status: null });
  check('handles are escaped in rows', !hostileRow.includes('<img'),
    hostileRow.slice(0, 200));

  console.log('== stat deltas ==');
  const stats = sandbox.statCardsHtml(
    { checks: 5, baseline_at: '2026-10-24T14:09:00' },
    [{ payload: { follower_count: 1211, following_count: 342 } },
     { payload: { follower_count: 1204, following_count: 342 } }],
    { ok: true, lists: { followers: { added: ['x'] }, following: { added: [] } },
      posts: { added_count: 0 } });
  check('deltas read against the last check',
    stats.includes('+7 vs last check') && stats.includes('· no change vs last check'),
    stats);
  check('an unread count never renders a number', !stats.includes('Posts'), stats);
  check('the checks card carries the baseline',
    stats.includes('Checks') && stats.includes('baseline 24 Oct · 14:09'), stats);
  check('only panels that exist get a chevron',
    stats.includes('data-toggle="followers"') && !stats.includes('data-toggle="following"'),
    stats);

  console.log('== diff verdicts render as the engine worded them ==');
  const refusal = sandbox.dashDiffHtml(
    { ok: false, changed: false,
      error: 'no previous check to compare against — this run is the baseline' },
    null, []);
  check('a refusal renders as a refusal',
    refusal.includes('diff-none') && refusal.includes('this run is the baseline'),
    refusal);
  const unchanged = sandbox.dashDiffHtml(
    { ok: true, changed: false, counts: [{ key: 'follower_count', delta: 0 }],
      lists: {}, posts: { added: [], added_count: 0 }, fields: [],
      walls: { new: [], resolved: [] } },
    { handle: 'u' }, [{ payload: {} }, { taken_at: '2026-10-27T11:30:00', payload: {} }]);
  check('no change says no change, not an empty box',
    unchanged.includes('No changes since the previous check'), unchanged);
  const countsOnly = sandbox.dashDiffHtml(
    { ok: true, changed: true, counts: [{ key: 'follower_count', delta: 5 }],
      lists: {}, posts: { added: [], added_count: 0 }, fields: [],
      walls: { new: [], resolved: [] } },
    { handle: 'u' }, [{ payload: {} }, { taken_at: '2026-10-27T11:30:00', payload: {} }]);
  check('count-only movement points at the stats',
    countsOnly.includes('Count changes only'), countsOnly);
  const changed = sandbox.dashDiffHtml(
    { ok: true, changed: true, counts: [],
      lists: { followers: { added: ['nova.bsky.social'], removed: ['ghost.bsky.social'],
                            added_refused: null, removed_refused: null } },
      posts: { added: [], added_count: 0 }, fields: [],
      walls: { new: [], resolved: [] } },
    { handle: 'u' },
    [{ payload: {} }, { taken_at: '2026-10-24T14:09:00', payload: {} }]);
  check('additions and removals render as rows',
    changed.includes('new follower') && changed.includes('unfollowed')
    && changed.includes('nova.bsky.social') && changed.includes('since 24 Oct · 14:09'),
    changed);
  const gated = sandbox.dashDiffHtml(
    { ok: true, changed: false, counts: [],
      lists: { followers: { added: [], removed: [],
                            added_refused: 'baseline followers list was not fully enumerated — additions cannot be claimed',
                            removed_refused: null } },
      posts: { added: [], added_count: 0 }, fields: [],
      walls: { new: [], resolved: [] } },
    { handle: 'u' },
    [{ payload: {} }, { taken_at: '2026-10-24T14:09:00', payload: {} }]);
  check('a refused side explains itself instead of claiming no change',
    gated.includes('no diff claimed')
    && gated.includes('additions cannot be claimed'), gated);
  const injected = sandbox.dashDiffHtml(
    { ok: true, changed: true, counts: [],
      lists: { followers: { added: ['<img src=x onerror=alert(1)>'], removed: [],
                            added_refused: null, removed_refused: null } },
      posts: { added: [], added_count: 0 }, fields: [],
      walls: { new: [], resolved: [] } },
    { handle: 'u' },
    [{ payload: {} }, { taken_at: '2026-10-24T14:09:00', payload: {} }]);
  check('diff rows escape handles', !injected.includes('<img'), injected.slice(0, 300));

  console.log('== history rail ==');
  const rail = sandbox.historyRailHtml({ handle: 'u' }, [
    { taken_at: '2026-10-28T08:29:00', payload: { follower_count: 1211, status: 'ok' } },
    { taken_at: '2026-10-24T14:09:00', payload: { follower_count: 1204 } },
  ]);
  check('history reads newest → oldest (latest at the top)',
    rail.indexOf('28 Oct · 08:29') < rail.indexOf('24 Oct · 14:09'), rail);
  check('the oldest card is the baseline',
    rail.includes('Baseline established') && rail.includes('followers'), rail);
  check('later cards show count deltas', rail.includes('+7 followers'), rail);
  check('the newest card is marked latest and selected',
    rail.includes('tl-tag') && rail.indexOf('class="tl-row active"') > -1
    && rail.indexOf('data-hist-index="0"') > -1, rail);
  check('an empty history renders nothing',
    sandbox.historyRailHtml({ handle: 'u' }, []) === '',
    sandbox.historyRailHtml({ handle: 'u' }, []));

  console.log('== timeline selection rewinds the main column ==');
  const rewound = sandbox.statCardsHtml(
    { checks: 2, baseline_at: '2026-10-24T14:09:00' },
    [{ taken_at: '2026-10-28T08:29:00', payload: { follower_count: 1211 } },
     { taken_at: '2026-10-24T14:09:00', payload: { follower_count: 1204 } }],
    null, 1);
  check('an older check shows its own counts',
    rewound.includes('1,204') && !rewound.includes('1,211'), rewound);
  check('an older check says it is showing that check',
    rewound.includes('showing 24 Oct · 14:09'), rewound);
  const rewoundDiff = sandbox.dashDiffHtml(
    { ok: false, changed: false, error: 'no previous check' },
    { handle: 'u' },
    [{ taken_at: '2026-10-28T08:29:00', payload: {} },
     { taken_at: '2026-10-24T14:09:00', payload: {} }], 1);
  check('the oldest retained check reads as the baseline',
    rewoundDiff.includes('Baseline recorded') && !rewoundDiff.includes('no previous check'),
    rewoundDiff);

  console.log('== media follows the selected check ==');
  const media = sandbox.mediaPanelHtml({ id: 7 }, {
    taken_at: '2026-10-29T22:22:00',
    payload: {
      capabilities: ['media', 'stories'],
      stories: { count: 1, items: [
        { id: 's1', taken_at: 1791478000, file: 'output/u/media/stories/story_s1.jpg' },
      ] },
      posts: [{ caption: 'boat', timestamp: 1791478332,
                media_files: ['output/u/media/abc.jpg'] }],
    },
  }, 'instagram');
  check('story files render as media tiles',
    media.includes('/api/social/media/7') && media.includes('story_s1.jpg')
    && media.includes('>Stories<'), media);
  check('post files render beside their check', media.includes('boat'), media);
  const legacyMedia = sandbox.mediaPanelHtml({ id: 7 }, {
    taken_at: '2026-10-29T22:22:00',
    payload: { capabilities: ['media', 'stories'], posts: [{ caption: 'old' }] },
  }, 'instagram');
  check('a snapshot without story capture says so',
    legacyMedia.includes('predates story capture'), legacyMedia);
  check('a snapshot without per-post files says so',
    legacyMedia.includes('predates per-post media capture'), legacyMedia);
  const noStories = sandbox.mediaPanelHtml({ id: 7 }, {
    taken_at: '2026-10-29T22:22:00',
    payload: { capabilities: ['media', 'stories'], stories: { count: 0, items: [] },
               posts: [{ caption: 'x', media_files: [] }] },
  }, 'instagram');
  check('an empty story tray is not "not captured"',
    noStories.includes('No active stories') && !noStories.includes('predates'),
    noStories);

  console.log('== dashboard header says one true thing ==');
  (function () {
    const els = {};
    ['socialPlatformName', 'socialHandleTitle', 'socialCheckBtn',
     'socialBurnerPill', 'socialWhen'].forEach((id) => {
      els[id] = { textContent: '', innerHTML: '', hidden: false, disabled: false };
    });
    const realGet = sandbox.document.getElementById;
    sandbox.document.getElementById = (id) => els[id] || null;
    try {
      sandbox.paintDashboardHead('instagram', {
        handle: 'qrxznat', checks: 0, baseline_at: null,
        last_check_at: '2026-10-29T21:53:00',
        last_status: 'stealth browser unavailable (exit 1)',
      }, {});
      check('a failed first attempt explains itself',
        els.socialWhen.innerHTML.includes('no baseline yet')
        && els.socialWhen.innerHTML.includes('last attempt failed')
        && els.socialWhen.innerHTML.includes('exit 1'), els.socialWhen.innerHTML);
      check('no phantom last-check time beside zero checks',
        !els.socialWhen.innerHTML.includes('last check'), els.socialWhen.innerHTML);
      check('the baseline is never painted red',
        !els.socialWhen.innerHTML.includes('past'), els.socialWhen.innerHTML);
      sandbox.paintDashboardHead('instagram', {
        handle: 'qrxznat', checks: 3, last_status: 'ok',
        last_check_at: '2026-10-29T21:53:00',
        baseline_at: '2026-10-27T22:15:00',
      }, {});
      check('a healthy target shows both stamps on one line',
        els.socialWhen.innerHTML.includes('last check')
        && els.socialWhen.innerHTML.includes('baseline')
        && els.socialWhen.innerHTML.includes('27 Oct · 22:15'),
        els.socialWhen.innerHTML);
      check('a healthy target reports no failure',
        !els.socialWhen.innerHTML.includes('failed'), els.socialWhen.innerHTML);
      sandbox.paintDashboardHead('instagram', null, {});
      check('no target hides the status line and locks the button',
        els.socialWhen.hidden === true && els.socialCheckBtn.disabled === true
        && els.socialHandleTitle.textContent === 'no target',
        JSON.stringify({ hidden: els.socialWhen.hidden,
                         subject: els.socialHandleTitle.textContent }));
    } finally {
      sandbox.document.getElementById = realGet;
    }
  })();

  console.log('== the unchecked dashboard says it once ==');
  const emptyStats = sandbox.statCardsHtml({ checks: 0, baseline_at: null }, [], null);
  check('no checks → no stat row at all', emptyStats === '', emptyStats);
  const noChecks = sandbox.dashDiffHtml(null, { handle: 'u' }, []);
  check('the no-check blank is one short line',
    noChecks.includes('No baseline yet') && noChecks.length < 220, noChecks);
  const oneCheck = sandbox.dashDiffHtml(
    { ok: false, changed: false,
      error: 'no previous check to compare against — this run is the baseline' },
    { handle: 'u' }, [{ payload: {} }]);
  check('a recorded baseline reads as a state, not an engine refusal',
    oneCheck.includes('Baseline recorded') && !oneCheck.includes('diff-none'), oneCheck);

  console.log('== check payload: options in, burner only where a login exists ==');
  const realGet = sandbox.document.getElementById;
  const realFetch = sandbox.fetch;
  const realMeta = sandbox.SOCIAL_META;
  const formEl = {
    querySelectorAll: (sel) => (sel === '[data-flag]' ? [
      { type: 'checkbox', checked: true, getAttribute: () => 'deep' },
      { type: 'checkbox', checked: false, getAttribute: () => 'store' },
    ] : []),
  };
  sandbox.document.getElementById = (id) => (id === 'form-social' ? formEl : null);
  sandbox.SOCIAL_META = {
    instagram: { browser: true, login: 'instacloak' },
    bluesky: { browser: false, login: 'none' },
  };
  try {
    const plain = sandbox.buildCheckPayload('bluesky');
    check('checked options ride the payload',
      plain.deep === '1' && plain.store === undefined, JSON.stringify(plain));
    check('no burner is attached without a stored login',
      plain.burner_enabled === undefined, JSON.stringify(plain));
    sandbox.localStorage.getItem = (k) => (
      k === 'spyglass_burner'
        ? JSON.stringify({ enabled: true, username: 'ops', password: 'hunter2' })
        : null);
    const insta = sandbox.buildCheckPayload('instagram');
    check('the burner rides a login platform',
      insta.burner_enabled === '1' && insta.burner_username === 'ops',
      JSON.stringify(insta));
    const keyless = sandbox.buildCheckPayload('bluesky');
    check('the burner stays off keyless tabs even when configured',
      keyless.burner_enabled === undefined, JSON.stringify(keyless));
  } finally {
    sandbox.document.getElementById = realGet;
    sandbox.fetch = realFetch;
    sandbox.SOCIAL_META = realMeta;
    sandbox.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  }

  console.log('== a dead store resolves into a blank state ==');
  sandbox.document.getElementById = () => null;
  sandbox.fetch = () => Promise.reject(new Error('no network in tests'));
  try {
    const pending = sandbox.loadSocialDashboard('mastodon');
    check('loadSocialDashboard returns a promise',
      !!pending && typeof pending.then === 'function', String(pending));
    await pending;
    check('a dead target store resolves instead of rejecting', true);
  } catch (err) {
    check('a dead target store resolves instead of rejecting', false, String(err));
  } finally {
    sandbox.document.getElementById = realGet;
    sandbox.fetch = realFetch;
  }
})();

/* The registry-failure test and the target-flow test above are both
 * asynchronous; let their checks land before the tally prints, so the
 * summary matches what actually ran. */
Promise.all([registryFetchTest, targetFlowTest]).then(function () {
  console.log(`\n${'='.repeat(40)}\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
});