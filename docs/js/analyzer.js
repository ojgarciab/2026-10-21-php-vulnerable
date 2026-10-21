/*
 * Analizador de php.ini para las mitigaciones de PHP2Shell
 * (CVE-2026-109618 / CVE-2026-109619).
 *
 * Módulo sin dependencias, ejecutable en navegador (window.PhpIniAnalyzer)
 * y en Node.js (module.exports). Los textos se cargan desde los ficheros
 * de idioma js/locale-*.js, que se registran con registerLocale().
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhpIniAnalyzer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FIXED_VERSIONS = { '8.5': '8.5.12', '8.4': '8.4.27', '8.3': '8.3.36', '8.2': '8.2.35' };
  const CVES = {
    'CVE-2026-109618': { id: 'CVE-2026-109618', ghsa: 'GHSA-w8hw-w9fx-j79w' },
    'CVE-2026-109619': { id: 'CVE-2026-109619', ghsa: 'GHSA-6wmf-4rv5-p3rp' },
  };

  const locales = {};
  function registerLocale(code, data) { locales[code] = data; }
  function getLocale(code) {
    const l = locales[code] || locales.es || locales[Object.keys(locales)[0]];
    if (!l) throw new Error('No locale registered');
    return l;
  }

  /* ------------------------------------------------------------------ */
  /* Utilidades de valores INI                                           */
  /* ------------------------------------------------------------------ */

  function stripQuotes(v) {
    v = v.trim();
    if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
      return v.slice(1, -1);
    }
    return v;
  }

  function iniBool(v) {
    if (v === undefined || v === null) return null;
    const s = stripQuotes(String(v)).toLowerCase();
    if (['1', 'on', 'yes', 'true'].includes(s)) return true;
    if (['0', 'off', 'no', 'false', 'none', ''].includes(s)) return false;
    const n = Number(s);
    if (!Number.isNaN(n)) return n !== 0;
    return null;
  }

  function iniBytes(v) {
    if (v === undefined || v === null) return null;
    const s = stripQuotes(String(v)).trim();
    if (s === '') return null;
    const m = /^(-?\d+)\s*([kmg]?)$/i.exec(s);
    if (!m) return null;
    let n = parseInt(m[1], 10);
    if (n < 0) return Infinity;
    const unit = m[2].toLowerCase();
    if (unit === 'k') n *= 1024;
    else if (unit === 'm') n *= 1024 * 1024;
    else if (unit === 'g') n *= 1024 * 1024 * 1024;
    return n;
  }

  function iniInt(v) {
    if (v === undefined || v === null) return null;
    const s = stripQuotes(String(v)).trim();
    if (!/^-?\d+$/.test(s)) return null;
    return parseInt(s, 10);
  }

  function fmtBytes(n, L) {
    if (n === Infinity) return L.bytes.unlimited;
    if (n === null) return L.bytes.unknown;
    if (n % (1024 * 1024 * 1024) === 0) return n / (1024 * 1024 * 1024) + 'G';
    if (n % (1024 * 1024) === 0) return n / (1024 * 1024) + 'M';
    if (n % 1024 === 0) return n / 1024 + 'K';
    return n + ' bytes';
  }

  /* ------------------------------------------------------------------ */
  /* Parser línea a línea (conserva comentarios y orden)                 */
  /* ------------------------------------------------------------------ */

  function splitValueComment(raw) {
    let inQ = null;
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (inQ) {
        if (c === inQ) inQ = null;
      } else if (c === '"' || c === "'") {
        inQ = c;
      } else if (c === ';') {
        return { value: raw.slice(0, i).trim(), comment: raw.slice(i) };
      }
    }
    return { value: raw.trim(), comment: '' };
  }

  function parse(text) {
    const lines = text.split(/\r?\n/);
    const eol = /\r\n/.test(text) ? '\r\n' : '\n';
    const entries = [];
    let section = null;
    lines.forEach((line, idx) => {
      const t = line.trim();
      const entry = { index: idx, raw: line, type: 'other', section };
      if (t === '') {
        entry.type = 'blank';
      } else if (t[0] === ';' || t[0] === '#') {
        entry.type = 'comment';
        const m = /^[;#]\s*([A-Za-z_][\w.]*)\s*=\s*(.*)$/.exec(t);
        if (m) {
          entry.commentedKey = m[1].toLowerCase();
          entry.commentedValue = splitValueComment(m[2]).value;
        }
      } else if (t[0] === '[') {
        entry.type = 'section';
        const m = /^\[([^\]]*)\]/.exec(t);
        section = m ? m[1].trim() : t;
        entry.section = section;
        entry.name = section;
      } else {
        const eq = t.indexOf('=');
        if (eq > 0) {
          const key = t.slice(0, eq).trim();
          const { value, comment } = splitValueComment(t.slice(eq + 1));
          entry.type = 'directive';
          entry.key = key.toLowerCase();
          entry.originalKey = key;
          entry.value = value;
          entry.comment = comment;
        }
      }
      entries.push(entry);
    });
    return { entries, eol };
  }

  function isConditionalSection(name) {
    return !!name && /^(PATH|HOST)\s*=/i.test(name);
  }

  function findDirective(parsed, key) {
    let found = null;
    for (const e of parsed.entries) {
      if (e.type === 'directive' && e.key === key && !isConditionalSection(e.section)) found = e;
    }
    return found;
  }

  function findConditional(parsed, key) {
    return parsed.entries.filter((e) => e.type === 'directive' && e.key === key && isConditionalSection(e.section));
  }

  /* ------------------------------------------------------------------ */
  /* Reglas (la lógica aquí; los textos en los ficheros de idioma)       */
  /* ------------------------------------------------------------------ */

  // check() devuelve { status, msg?, params? }; msg es la clave del texto en el idioma.
  const RULES = [
    {
      key: 'session.upload_progress.enabled', cve: 'CVE-2026-109619', severity: 'critica', suggested: 'Off', scope: 'PHP_INI_PERDIR',
      check(ctx) {
        if (!ctx.present) return { status: 'add', msg: 'add' };
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
    {
      key: 'memory_limit', cve: 'CVE-2026-109618', severity: 'critica', suggested: '-1', scope: 'PHP_INI_ALL',
      check(ctx) {
        if (!ctx.present) return { status: 'add', msg: 'add' };
        const n = iniBytes(ctx.value);
        if (n === Infinity) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value, bytes: fmtBytes(n, ctx.L) } };
      },
    },
    {
      key: 'post_max_size', cve: 'CVE-2026-109618', severity: 'alta', suggested: '8M', scope: 'PHP_INI_PERDIR', max: 8 * 1024 * 1024,
      check(ctx) {
        if (!ctx.present) return { status: 'add', msg: 'add' };
        const n = iniBytes(ctx.value);
        if (n !== null && n !== Infinity && n <= this.max) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value, bytes: fmtBytes(n, ctx.L) } };
      },
    },
    {
      key: 'upload_max_filesize', cve: 'CVE-2026-109618', severity: 'alta', suggested: '2M', scope: 'PHP_INI_PERDIR', max: 2 * 1024 * 1024,
      check(ctx) {
        if (!ctx.present) return { status: 'add', msg: 'add' };
        const n = iniBytes(ctx.value);
        if (n !== null && n !== Infinity && n <= this.max) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value, bytes: fmtBytes(n, ctx.L) } };
      },
    },
    {
      key: 'max_file_uploads', cve: 'CVE-2026-109618', severity: 'alta', suggested: '20', scope: 'PHP_INI_SYSTEM', max: 20,
      check(ctx) {
        if (!ctx.present) return { status: 'add', msg: 'add' };
        const n = iniInt(ctx.value);
        if (n !== null && n >= 0 && n <= this.max) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
    {
      key: 'max_input_vars', cve: 'CVE-2026-109618', severity: 'media', suggested: '1000', scope: 'PHP_INI_PERDIR', max: 1000,
      check(ctx) {
        if (!ctx.present) return { status: 'info', msg: 'info' };
        const n = iniInt(ctx.value);
        if (n !== null && n <= this.max) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
    {
      key: 'fatal_error_backtraces', cve: 'CVE-2026-109619', severity: 'alta', suggested: 'Off', scope: 'PHP_INI_ALL',
      check(ctx) {
        if (ctx.version && ctx.version !== '8.5' && ctx.version !== 'unknown') return { status: 'skip', msg: 'skip' };
        if (!ctx.present) {
          return ctx.version === '8.5' ? { status: 'add', msg: 'add' } : { status: 'info', msg: 'info' };
        }
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
    {
      key: 'file_uploads', cve: 'CVE-2026-109618', severity: 'media', suggested: 'Off', scope: 'PHP_INI_SYSTEM',
      check(ctx) {
        if (!ctx.present) return { status: 'info', msg: 'infoAbsent' };
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'info', msg: 'infoOn' };
      },
    },
    {
      key: 'expose_php', cve: null, severity: 'baja', suggested: 'Off', scope: 'PHP_INI_SYSTEM',
      check(ctx) {
        if (!ctx.present) return { status: 'add', msg: 'add' };
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'change', msg: 'change', params: { value: ctx.value } };
      },
    },
  ];

  function tpl(str, params) {
    return String(str || '').replace(/\{(\w+)\}/g, (m, k) => (params && k in params ? params[k] : m));
  }

  /* ------------------------------------------------------------------ */
  /* Análisis                                                            */
  /* ------------------------------------------------------------------ */

  function analyze(text, options) {
    options = options || {};
    const version = options.version || 'unknown';
    const L = getLocale(options.locale);
    const parsed = parse(text);
    const findings = [];

    for (const rule of RULES) {
      const entry = findDirective(parsed, rule.key);
      const conditional = findConditional(parsed, rule.key);
      const r = rule.check({ present: !!entry, value: entry ? entry.value : undefined, version, L });
      const T = L.rules[rule.key];
      findings.push({
        key: rule.key,
        cve: rule.cve,
        severity: rule.severity,
        category: T.category,
        suggested: rule.suggested,
        scope: rule.scope,
        why: T.why,
        caveat: T.caveat,
        status: r.status,
        detail: r.msg ? tpl(T.details[r.msg], r.params) : '',
        line: entry ? entry.index + 1 : null,
        current: entry ? entry.value : null,
        conditionalLines: conditional.map((e) => e.index + 1),
        entry,
      });
    }

    return { parsed, findings, version, versionInfo: versionAdvice(version, L), locale: L };
  }

  function versionAdvice(version, L) {
    if (FIXED_VERSIONS[version]) {
      return { kind: 'supported', target: FIXED_VERSIONS[version], text: tpl(L.version.supported, { target: FIXED_VERSIONS[version] }) };
    }
    if (['7.4', '8.0', '8.1'].includes(version)) {
      return { kind: 'eol', target: null, text: tpl(L.version.eol, { version }) };
    }
    if (version === 'old') return { kind: 'eol', target: null, text: L.version.old };
    return { kind: 'unknown', target: null, text: L.version.unknown };
  }

  /* ------------------------------------------------------------------ */
  /* Generación del php.ini anotado                                      */
  /* ------------------------------------------------------------------ */

  function wrap(text, width, prefix) {
    const words = text.split(/\s+/);
    const out = [];
    let line = '';
    for (const w of words) {
      if ((line + ' ' + w).trim().length > width) {
        out.push(prefix + line.trim());
        line = w;
      } else {
        line = (line + ' ' + w).trim();
      }
    }
    if (line) out.push(prefix + line.trim());
    return out;
  }

  function annotate(text, options) {
    const result = analyze(text, options);
    const { parsed, findings, version, versionInfo } = result;
    const L = result.locale;
    const A = L.annotate;
    const eol = parsed.eol;
    const out = [];
    const today = (options && options.date) || new Date().toISOString().slice(0, 10);

    function commentBlock(f, action) {
      const lines = [];
      lines.push(';; --- PHP2Shell: ' + action + ' [' + L.severity[f.severity] + '] ---');
      if (f.cve) lines.push(';; ' + f.cve + ' (' + CVES[f.cve].ghsa + ')');
      if (f.detail) lines.push(...wrap(A.reason + ' ' + f.detail, 76, ';; '));
      lines.push(...wrap(f.why, 76, ';; '));
      lines.push(...wrap(A.caution + ' ' + f.caveat, 76, ';; '));
      return lines;
    }

    const rule = ';; ==========================================================================';
    out.push(rule);
    for (const l of A.header) out.push(';; ' + l);
    out.push(';; ' + tpl(A.generated, { date: today, version: version === 'unknown' ? A.versionNotGiven : version }));
    out.push(';;');
    out.push(...wrap(versionInfo.text, 76, ';; '));
    out.push(';;');
    for (const l of A.disclaimer) out.push(';; ' + l);
    out.push(rule);
    out.push('');

    const byLine = new Map();
    for (const f of findings) if (f.entry) byLine.set(f.entry.index, f);

    const pending = findings.filter((f) => !f.entry && (f.status === 'add' || f.status === 'info'));
    const placed = new Set();

    function addedBlock(f) {
      const block = [];
      if (f.status === 'add') {
        block.push(...commentBlock(f, A.actionAdded));
        block.push(f.key + ' = ' + f.suggested);
      } else {
        block.push(...commentBlock(f, A.actionOptional));
        block.push(';' + f.key + ' = ' + f.suggested);
      }
      block.push(A.end);
      return block;
    }

    const firstCond = parsed.entries.findIndex((e) => e.type === 'section' && isConditionalSection(e.name));
    let condInsertPos = -1;

    for (const e of parsed.entries) {
      if (e.index === firstCond) condInsertPos = out.length;
      const f = byLine.get(e.index);
      if (!f) {
        out.push(e.raw);
        if (e.type === 'comment' && e.commentedKey && !isConditionalSection(e.section)) {
          const pf = pending.find((x) => x.key === e.commentedKey && !placed.has(x.key));
          if (pf) {
            placed.add(pf.key);
            out.push(...addedBlock(pf));
          }
        }
        continue;
      }
      if (f.status === 'ok') {
        out.push(e.raw + ' ' + A.okInline);
      } else if (f.status === 'change') {
        out.push(...commentBlock(f, A.actionChange));
        out.push(';;OLD ' + e.raw);
        out.push(e.originalKey + ' = ' + f.suggested);
        out.push(A.end);
      } else if (f.status === 'info') {
        out.push(...commentBlock(f, A.actionReview));
        out.push(';; ' + A.suggestionIfApplicable + ' ' + e.originalKey + ' = ' + f.suggested);
        out.push(e.raw);
        out.push(A.end);
      } else {
        out.push(e.raw);
      }
    }

    const toAdd = pending.filter((f) => !placed.has(f.key));
    if (toAdd.length) {
      const block = [''];
      block.push(rule);
      for (const l of A.missingHeader) block.push(';; ' + l);
      block.push(rule);
      for (const f of toAdd) {
        block.push('');
        block.push(...addedBlock(f));
      }
      const lastSection = [...parsed.entries].reverse().find((e) => e.type === 'section');
      if (lastSection && isConditionalSection(lastSection.name) && condInsertPos >= 0) {
        out.splice(condInsertPos, 0, ...block, '');
      } else {
        out.push(...block);
      }
    }

    const cond = findings.filter((f) => f.conditionalLines.length);
    if (cond.length) {
      out.push('');
      for (const l of A.conditionalWarning) out.push(';; ' + l);
      for (const f of cond) out.push(';;   ' + tpl(A.conditionalLine, { key: f.key, lines: f.conditionalLines.join(', ') }));
    }

    out.push('');
    for (const l of A.footer) out.push(';; ' + l);

    let output = out.join(eol);
    if (!output.endsWith(eol)) output += eol;
    return { output, result };
  }

  return { parse, analyze, annotate, iniBool, iniBytes, iniInt, fmtBytes, registerLocale, getLocale, RULES, CVES, FIXED_VERSIONS };
});
