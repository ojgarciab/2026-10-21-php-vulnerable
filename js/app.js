/* Lógica de la interfaz. Todo se ejecuta en el navegador; no hay ningún envío a servidor. */
(function () {
  'use strict';
  const A = window.PhpIniAnalyzer;
  const $ = (s) => document.querySelector(s);

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

  const STATUS = {
    ok: { label: 'OK', cls: 'st-ok' },
    change: { label: 'Cambiar', cls: 'st-change' },
    add: { label: 'Añadir', cls: 'st-add' },
    info: { label: 'Revisar', cls: 'st-info' },
    skip: { label: 'No aplica', cls: 'st-skip' },
  };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function readFile(file) {
    if (!file) return;
    lastName = file.name || 'php.ini';
    fileName.textContent = file.name + ' (' + file.size + ' bytes)';
    const reader = new FileReader();
    reader.onload = () => {
      textarea.value = reader.result;
      run();
    };
    reader.readAsText(file);
  }

  fileInput.addEventListener('change', () => readFile(fileInput.files[0]));
  ['dragenter', 'dragover'].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('over'); })
  );
  ['dragleave', 'drop'].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('over'); })
  );
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
    fileName.textContent = 'Ejemplo cargado (php.ini-production)';
    run();
  });
  $('#btn-clear').addEventListener('click', () => {
    textarea.value = '';
    fileInput.value = '';
    fileName.textContent = 'Ningún fichero seleccionado';
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
    const base = lastName.replace(/\.ini$/i, '');
    a.href = url;
    a.download = base + '.php2shell-anotado.ini';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $('#btn-copy').addEventListener('click', async () => {
    if (!lastOutput) return;
    try {
      await navigator.clipboard.writeText(lastOutput);
      $('#btn-copy').textContent = 'Copiado ✓';
      setTimeout(() => ($('#btn-copy').textContent = 'Copiar al portapapeles'), 1500);
    } catch (e) {
      preview.classList.remove('hidden');
      alert('No se pudo acceder al portapapeles; copia el texto de la vista previa.');
    }
  });
  $('#btn-toggle-preview').addEventListener('click', () => preview.classList.toggle('hidden'));

  function run() {
    const text = textarea.value;
    if (!text.trim()) {
      alert('Carga o pega primero el contenido de un php.ini.');
      return;
    }
    const { output, result } = A.annotate(text, { version: versionSel.value });
    lastOutput = output;
    render(result);
    preview.textContent = output;
    resultCard.classList.remove('hidden');
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function render(result) {
    const banner = $('#version-banner');
    banner.className = 'banner ' + result.versionInfo.kind;
    banner.innerHTML = '<strong>Versión de PHP:</strong> ' + esc(result.versionInfo.text);

    const counts = {};
    result.findings.forEach((f) => { counts[f.status] = (counts[f.status] || 0) + 1; });
    $('#summary').innerHTML = Object.keys(STATUS)
      .filter((k) => counts[k])
      .map((k) => '<span class="pill ' + STATUS[k].cls + '">' + STATUS[k].label + ': ' + counts[k] + '</span>')
      .join('');

    tbody.innerHTML = '';
    result.findings.forEach((f) => {
      const st = STATUS[f.status];
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td data-label="Estado"><span class="pill ' + st.cls + '">' + st.label + '</span></td>' +
        '<td data-label="Directiva"><code>' + esc(f.key) + '</code></td>' +
        '<td data-label="Línea">' + (f.line ? f.line : '—') + (f.conditionalLines.length ? ' <span class="muted" title="También definida en secciones [PATH=]/[HOST=]">(+' + f.conditionalLines.join(', ') + ')</span>' : '') + '</td>' +
        '<td data-label="Valor actual">' + (f.current !== null ? '<code>' + esc(f.current === '' ? '(vacío)' : f.current) + '</code>' : '<span class="muted">no definida</span>') + '</td>' +
        '<td data-label="Sugerido"><code>' + esc(f.suggested) + '</code></td>' +
        '<td data-label="CVE">' + (f.cve ? '<a href="https://nvd.nist.gov/vuln/detail/' + esc(f.cve) + '" target="_blank" rel="noopener">' + esc(f.cve) + '</a>' : '—') + '</td>' +
        '<td data-label="Severidad"><span class="sev sev-' + esc(f.severity) + '">' + esc(A.SEV_LABEL[f.severity]) + '</span></td>';
      tbody.appendChild(tr);
      const d = document.createElement('tr');
      d.className = 'detail';
      d.innerHTML = '<td colspan="7">' + (f.detail ? '<strong>' + esc(f.detail) + '</strong> ' : '') + esc(f.why) + ' <em>' + esc(f.caveat) + '</em></td>';
      tbody.appendChild(d);
    });
  }

  // Documentación de reglas (sección "¿Qué comprueba?")
  function renderRulesDoc() {
    const el = $('#rules-doc');
    const cves = Object.values(A.CVES)
      .map((c) => '<details class="rule" open><summary>' + esc(c.id) + ' · ' + esc(c.title) + '</summary><p>' + esc(c.summary) + '</p><p class="muted">Aviso de PHP: ' + esc(c.ghsa) + '</p></details>')
      .join('');
    const rules = A.RULES.map(
      (r) =>
        '<details class="rule"><summary><code>' + esc(r.key) + ' = ' + esc(r.suggested) + '</code> · <span class="sev sev-' + r.severity + '">' + esc(A.SEV_LABEL[r.severity]) + '</span> · ' + esc(r.category) + (r.cve ? ' · ' + esc(r.cve) : '') + '</summary>' +
        '<p>' + esc(r.why) + '</p><p><strong>Atención:</strong> ' + esc(r.caveat) + '</p><p class="muted">Ámbito: ' + esc(r.scope) + '</p></details>'
    ).join('');
    el.innerHTML = '<h3>Vulnerabilidades</h3>' + cves + '<h3>Directivas analizadas</h3>' + rules;
  }
  renderRulesDoc();
})();
