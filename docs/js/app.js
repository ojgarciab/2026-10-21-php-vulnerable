/* Lógica de la interfaz, común a todos los idiomas. El idioma se toma del atributo
 * lang de <html>; los textos dinámicos vienen del fichero locale-<idioma>.js. */
(function () {
  'use strict';
  const A = window.PhpIniAnalyzer;
  const LANG = document.documentElement.lang || 'es';
  const L = A.getLocale(LANG);
  const $ = (s) => document.querySelector(s);

  // Recordar el idioma elegido para que la raíz redirija aquí la próxima vez.
  try { localStorage.setItem('php2shell-lang', LANG); } catch (e) { /* sin almacenamiento */ }

  const fileInput = $('#file-input');
  const dropzone = $('#dropzone');
  const fileName = $('#file-name');
  const textarea = $('#ini-text');
  const versionSel = $('#version');
  const resultCard = $('#result-card');
  const preview = $('#preview');
  const tbody = $('#findings tbody');

  let lastOutput = '';
  let lastName = 'php.ini';

  const STATUS_CLASS = { ok: 'st-ok', change: 'st-change', add: 'st-add', info: 'st-info', skip: 'st-skip' };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function readFile(file) {
    if (!file) return;
    lastName = file.name || 'php.ini';
    fileName.textContent = file.name + ' (' + file.size + ' bytes)';
    const reader = new FileReader();
    reader.onload = () => { textarea.value = reader.result; run(); };
    reader.readAsText(file);
  }

  fileInput.addEventListener('change', () => readFile(fileInput.files[0]));
  ['dragenter', 'dragover'].forEach((ev) => dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('over'); }));
  dropzone.addEventListener('drop', (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) readFile(f);
  });
  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
  });

  $('#btn-sample').addEventListener('click', () => {
    textarea.value = window.PHP_INI_SAMPLE || '';
    lastName = 'php.ini';
    fileName.textContent = L.ui.sampleLoaded;
    run();
  });
  $('#btn-clear').addEventListener('click', () => {
    textarea.value = '';
    fileInput.value = '';
    fileName.textContent = L.ui.noFile;
    resultCard.classList.add('hidden');
    lastOutput = '';
  });
  $('#btn-analyze').addEventListener('click', run);
  versionSel.addEventListener('change', () => { if (textarea.value.trim()) run(); });

  $('#btn-download').addEventListener('click', () => {
    if (!lastOutput) return;
    const blob = new Blob([lastOutput], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = lastName.replace(/\.ini$/i, '') + L.ui.downloadSuffix;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $('#btn-copy').addEventListener('click', async () => {
    if (!lastOutput) return;
    try {
      await navigator.clipboard.writeText(lastOutput);
      $('#btn-copy').textContent = L.ui.copied;
      setTimeout(() => ($('#btn-copy').textContent = L.ui.copy), 1500);
    } catch (e) {
      preview.classList.remove('hidden');
      alert(L.ui.clipboardError);
    }
  });
  $('#btn-toggle-preview').addEventListener('click', () => preview.classList.toggle('hidden'));

  function run() {
    const text = textarea.value;
    if (!text.trim()) { alert(L.ui.emptyAlert); return; }
    const { output, result } = A.annotate(text, { version: versionSel.value, locale: LANG });
    lastOutput = output;
    render(result);
    preview.textContent = output;
    resultCard.classList.remove('hidden');
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function render(result) {
    const banner = $('#version-banner');
    banner.className = 'banner ' + result.versionInfo.kind;
    banner.innerHTML = '<strong>' + esc(L.ui.phpVersion) + '</strong> ' + esc(result.versionInfo.text);

    const counts = {};
    result.findings.forEach((f) => { counts[f.status] = (counts[f.status] || 0) + 1; });
    $('#summary').innerHTML = Object.keys(STATUS_CLASS)
      .filter((k) => counts[k])
      .map((k) => '<span class="pill ' + STATUS_CLASS[k] + '">' + esc(L.status[k]) + ': ' + counts[k] + '</span>')
      .join('');

    const labels = [...document.querySelectorAll('#findings thead th')].map((th) => th.textContent);
    tbody.innerHTML = '';
    result.findings.forEach((f) => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td data-label="' + esc(labels[0]) + '"><span class="pill ' + STATUS_CLASS[f.status] + '">' + esc(L.status[f.status]) + '</span></td>' +
        '<td data-label="' + esc(labels[1]) + '"><code>' + esc(f.key) + '</code></td>' +
        '<td data-label="' + esc(labels[2]) + '">' + (f.line ? f.line : '—') + (f.conditionalLines.length ? ' <span class="muted" title="' + esc(L.ui.alsoConditional) + '">(+' + f.conditionalLines.join(', ') + ')</span>' : '') + '</td>' +
        '<td data-label="' + esc(labels[3]) + '">' + (f.current !== null ? '<code>' + esc(f.current === '' ? L.ui.empty : f.current) + '</code>' : '<span class="muted">' + esc(L.ui.notDefined) + '</span>') + '</td>' +
        '<td data-label="' + esc(labels[4]) + '"><code>' + esc(f.suggested) + '</code></td>' +
        '<td data-label="' + esc(labels[5]) + '">' + (f.cve ? '<a href="https://nvd.nist.gov/vuln/detail/' + esc(f.cve) + '" target="_blank" rel="noopener">' + esc(f.cve) + '</a>' : '—') + '</td>' +
        '<td data-label="' + esc(labels[6]) + '"><span class="sev sev-' + esc(f.severity) + '">' + esc(L.severity[f.severity]) + '</span></td>';
      tbody.appendChild(tr);
      const d = document.createElement('tr');
      d.className = 'detail';
      d.innerHTML = '<td colspan="7">' + (f.detail ? '<strong>' + esc(f.detail) + '</strong> ' : '') + esc(f.why) + ' <em>' + esc(f.caveat) + '</em></td>';
      tbody.appendChild(d);
    });
  }

  function renderRulesDoc() {
    const el = $('#rules-doc');
    const cves = Object.keys(A.CVES)
      .map((id) => '<details class="rule" open><summary>' + esc(id) + ' · ' + esc(L.cves[id].title) + '</summary><p>' + esc(L.cves[id].summary) + '</p><p class="muted">' + esc(L.ui.phpAdvisory) + ' ' + esc(A.CVES[id].ghsa) + '</p></details>')
      .join('');
    const rules = A.RULES.map((r) => {
      const T = L.rules[r.key];
      return '<details class="rule"><summary><code>' + esc(r.key) + ' = ' + esc(r.suggested) + '</code> · <span class="sev sev-' + r.severity + '">' + esc(L.severity[r.severity]) + '</span> · ' + esc(T.category) + (r.cve ? ' · ' + esc(r.cve) : '') + '</summary>' +
        '<p>' + esc(T.why) + '</p><p><strong>' + esc(L.ui.caution) + '</strong> ' + esc(T.caveat) + '</p><p class="muted">' + esc(L.ui.scope) + ' ' + esc(r.scope) + '</p></details>';
    }).join('');
    el.innerHTML = '<h3>' + esc(L.ui.vulnerabilities) + '</h3>' + cves + '<h3>' + esc(L.ui.directives) + '</h3>' + rules;
  }
  renderRulesDoc();
})();
