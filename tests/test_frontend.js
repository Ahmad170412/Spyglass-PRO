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

console.log(`\n${'='.repeat(40)}\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);