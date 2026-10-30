// Local DOM behavior check; no browser, network resources or target code execute.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const modules = path.resolve(process.argv[3] || 'reports/report-dom-tools/node_modules');
const {JSDOM} = require(path.join(modules, 'jsdom'));
const html = fs.readFileSync(process.argv[2], 'utf8');
const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');
async function check(withGraph) {
  const dom = new JSDOM(html, {runScripts:'outside-only', pretendToBeVisual:true});
  const w = dom.window, d = w.document;
  const errors=[]; w.addEventListener('error', event => errors.push(event.error));
  if (withGraph) w.eval(fs.readFileSync(path.join(modules, 'd3/dist/d3.min.js'), 'utf8'));
  w.eval(inline);
  const rows = [...d.querySelectorAll('#vuln-table tbody tr')];
  const visible = () => rows.filter(r => r.style.display !== 'none');
  assert(rows.length > 0);
  assert.equal(visible().length, rows.length);
  assert(rows.every(r => r.cells.length === 5));
  assert(!d.querySelector('#dependency-map').open);
  assert(d.querySelector('#hide-clean-nodes').checked);
  assert.equal(d.querySelectorAll('#graph circle').length, 0);
  d.querySelector('#dependency-map').open = true;
  d.querySelector('#dependency-map').dispatchEvent(new w.Event('toggle'));
  if (withGraph) {
    assert(d.querySelectorAll('#graph circle').length > 0);
    assert(d.querySelectorAll('#graph circle').length <= 150);
    assert.equal(d.querySelectorAll('#graph circle[fill="#3fb950"]').length, 0);
    const circlesBefore = d.querySelectorAll('#graph circle').length;
    d.querySelector('#hide-clean-nodes').checked = false;
    d.querySelector('#hide-clean-nodes').dispatchEvent(new w.Event('change'));
    assert(d.querySelectorAll('#graph circle').length >= circlesBefore);
    if (d.querySelectorAll('#graph circle').length > 14) {
      assert([...d.querySelectorAll('#graph text')].some(t => t.style.visibility === 'hidden'));
    }
  } else assert(d.querySelector('#graph-note').textContent.includes('unavailable offline'));
  const search = d.querySelector('#finding-search');
  search.value = 'NONEXISTENT_79459'; search.dispatchEvent(new w.Event('input'));
  assert.equal(visible().length, 0);
  assert(!d.querySelector('#no-matches').hidden);
  search.value = ''; search.dispatchEvent(new w.Event('input'));
  assert.equal(visible().length, rows.length);
  const status = rows[0].dataset.status;
  d.querySelector('[data-filter-state="'+status+'"]').click();
  assert.equal(visible().length, rows.filter(r => r.dataset.status === status).length);
  const severity = d.querySelector('#severity-filter');
  severity.value = rows[0].dataset.severity; severity.dispatchEvent(new w.Event('change'));
  assert.equal(visible().length, rows.filter(r => r.dataset.status === status && r.dataset.severity === severity.value).length);
  d.querySelector('#clear-filter').click();
  assert.equal(visible().length, rows.length);
  const chip = d.querySelector('.package-chip');
  if (chip) {
    chip.click();
    assert.equal(visible().length, rows.filter(r => r.dataset.package === chip.dataset.package).length);
    d.querySelector('#clear-filter').click();
  }
  assert(d.querySelector('#results-count').textContent.includes(rows.length+' of '+rows.length));
  await new Promise(resolve => setTimeout(resolve, 30));
  if (w.depreachGraphSimulation) w.depreachGraphSimulation.stop();
  assert.deepEqual(errors, []);
  dom.window.close();
  return {withGraph, findings:rows.length, passed:true};
}
(async () => console.log(JSON.stringify([await check(false), await check(true)], null, 2)))().catch(error => {console.error(error); process.exitCode=1;});
