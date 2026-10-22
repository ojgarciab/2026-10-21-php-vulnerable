// Pruebas mínimas del analizador: node test/analyzer.test.js
const assert = require('node:assert/strict');
const A = require('../docs/js/analyzer.js');
const LOCALES = ['es', 'en', 'fr', 'it', 'de', 'pt'];
for (const c of LOCALES) A.registerLocale(c, require('../docs/js/locale-' + c + '.js'));

// Valores INI
assert.equal(A.iniBool('Off'), false);
assert.equal(A.iniBool('"1"'), true);
assert.equal(A.iniBool(''), false);
assert.equal(A.iniBytes('128M'), 128 * 1024 * 1024);
assert.equal(A.iniBytes('-1'), Infinity);
assert.equal(A.iniBytes('2G'), 2 * 1024 ** 3);
assert.equal(A.iniBytes('abc'), null);

// Parser: comentarios inline y última aparición prevalece
const ini = [
  '[PHP]',
  'memory_limit = 128M ; comentario',
  'post_max_size = "64M"',
  'memory_limit = 256M',
  ';session.upload_progress.enabled = On',
  '[HOST=www.example.com]',
  'memory_limit = -1',
].join('\n');
const parsed = A.parse(ini);
assert.equal(parsed.entries[1].value, '128M');
assert.equal(parsed.entries[1].comment, '; comentario');
assert.equal(parsed.entries[4].commentedKey, 'session.upload_progress.enabled');

const res = A.analyze(ini, { version: '8.3' });
const byKey = Object.fromEntries(res.findings.map((f) => [f.key, f]));
assert.equal(byKey.memory_limit.status, 'change');
assert.equal(byKey.memory_limit.line, 4);
assert.deepEqual(byKey.memory_limit.conditionalLines, [7]);
assert.equal(byKey.post_max_size.status, 'change');
assert.equal(byKey['session.upload_progress.enabled'].status, 'add');
assert.equal(byKey.fatal_error_backtraces.status, 'skip');
assert.equal(res.versionInfo.target, '8.3.36');

// Anotación: la salida debe ser un php.ini válido con los valores sugeridos como última aparición
const { output } = A.annotate(ini, { version: '8.3', date: '2026-10-21' });
const re = A.parse(output);
const last = (k) => [...re.entries].reverse().find((e) => e.type === 'directive' && e.key === k && !/^(PATH|HOST)=/i.test(e.section || ''));
assert.equal(last('memory_limit').value, '-1');
assert.equal(last('post_max_size').value, '8M');
assert.equal(last('session.upload_progress.enabled').value, 'Off');
assert.equal(last('expose_php').value, 'Off');
assert.ok(output.includes(';;OLD memory_limit = 256M'));
// El bloque añadido no debe quedar dentro de [HOST=...]
const hostIdx = re.entries.findIndex((e) => e.type === 'section' && /^HOST=/i.test(e.name));
const supIdx = re.entries.findIndex((e) => e.type === 'directive' && e.key === 'session.upload_progress.enabled');
assert.ok(supIdx < hostIdx, 'las directivas añadidas deben ir antes de la sección condicional');
assert.ok(output.includes('ATENCIÓN PHP2Shell'));

// Fichero ya seguro
const safe = ['memory_limit=-1', 'post_max_size=8M', 'upload_max_filesize=2M', 'max_file_uploads=5', 'session.upload_progress.enabled=0', 'expose_php=Off', 'fatal_error_backtraces=0'].join('\n');
const r2 = A.analyze(safe, { version: '8.5' });
assert.ok(r2.findings.filter((f) => ['change', 'add'].includes(f.status)).length === 0, 'no debería haber cambios');

// PHP 8.5 sin fatal_error_backtraces
const r3 = A.analyze('memory_limit=-1', { version: '8.5' });
assert.equal(Object.fromEntries(r3.findings.map((f) => [f.key, f])).fatal_error_backtraces.status, 'add');

// CRLF se conserva
const crlf = A.annotate('memory_limit = 128M\r\n', { version: 'unknown', date: '2026-10-21' }).output;
assert.ok(/\r\n/.test(crlf) && !/[^\r]\n/.test(crlf));

console.log('OK: todas las pruebas pasan');

// La directiva ausente se inserta bajo su versión comentada, si existe
const withCommented = ['memory_limit=-1', ';session.upload_progress.enabled = On', '[opcache]', 'opcache.enable=1'].join('\n');
const o4 = A.annotate(withCommented, { version: '8.3', date: '2026-10-21' }).output.split('\n');
const ci = o4.indexOf(';session.upload_progress.enabled = On');
const di = o4.indexOf('session.upload_progress.enabled = Off');
assert.ok(ci >= 0 && di > ci && di < o4.indexOf('[opcache]'), 'debe insertarse bajo la línea comentada');
console.log('OK: inserción bajo directiva comentada');

// Inglés: mismos resultados, textos traducidos
const en = A.annotate(ini, { version: '8.3', locale: 'en', date: '2026-10-21' });
assert.ok(en.output.includes('SUGGESTED CHANGE [CRITICAL]'));
assert.ok(!en.output.includes('CAMBIO SUGERIDO'));
assert.equal(en.result.findings.find((f) => f.key === 'memory_limit').detail, 'Current limit: 256M (256M).');
// Todas las claves de texto existen en ambos idiomas
for (const code of LOCALES) {
  const L = A.getLocale(code);
  for (const r of A.RULES) assert.ok(L.rules[r.key] && L.rules[r.key].why && L.rules[r.key].caveat && L.rules[r.key].details, code + ': ' + r.key);
  for (const id of Object.keys(A.CVES)) assert.ok(L.cves[id] && L.cves[id].title, code + ': ' + id);
  // Mismas claves que el español en todos los niveles
  const ref = A.getLocale('es');
  const keys = (o, p) => Object.keys(o).flatMap((k) => (o[k] && typeof o[k] === 'object' && !Array.isArray(o[k]) ? keys(o[k], p + k + '.') : [p + k]));
  assert.deepEqual(keys(L, '').sort(), keys(ref, '').sort(), code + ': claves distintas al español');
  // Anotación completa sin errores y con el php.ini resultante válido
  const o = A.annotate(ini, { version: '8.5', locale: code, date: '2026-10-21' }).output;
  const last = [...A.parse(o).entries].reverse().find((e) => e.type === 'directive' && e.key === 'memory_limit' && !/^HOST=/i.test(e.section || ''));
  assert.equal(last.value, '-1', code);
}
console.log('OK: ' + LOCALES.length + ' idiomas');
console.log('OK: locales es/en');
