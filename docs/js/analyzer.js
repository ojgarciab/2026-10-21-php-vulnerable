/*
 * Analizador de php.ini para las mitigaciones de PHP2Shell
 * (CVE-2026-109618 / CVE-2026-109619).
 *
 * Módulo sin dependencias, ejecutable en navegador (window.PhpIniAnalyzer)
 * y en Node.js (module.exports) para las pruebas automáticas.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhpIniAnalyzer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FIXED_VERSIONS = {
    '8.5': '8.5.12',
    '8.4': '8.4.27',
    '8.3': '8.3.36',
    '8.2': '8.2.35',
  };

  const CVES = {
    'CVE-2026-109618': {
      id: 'CVE-2026-109618',
      ghsa: 'GHSA-w8hw-w9fx-j79w',
      title: 'Corrupción de memoria tras agotar memory_limit durante el análisis multipart (RFC 1867)',
      summary:
        'Una petición multipart/form-data manipulada agota memory_limit mientras PHP todavía está ' +
        'inicializando los datos de la petición. El aborto deja estructuras parcialmente inicializadas ' +
        'que la limpieza final trata como válidas (use-after-free / puntero sin inicializar), lo que ' +
        'permite ejecución remota de código sin autenticación.',
    },
    'CVE-2026-109619': {
      id: 'CVE-2026-109619',
      ghsa: 'GHSA-6wmf-4rv5-p3rp',
      title: 'Estado global obsoleto reutilizado tras un error fatal (session.upload_progress / backtrace)',
      summary:
        'Tras un error fatal, parte del estado global de la petición (manejador de progreso de subida ' +
        'de sesión, backtrace del error fatal) sobrevive a la liberación de su memoria y la siguiente ' +
        'petición atendida por el mismo proceso trabajador la reutiliza. Permite ejecución remota de ' +
        'código sin autenticación.',
    },
  };

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

  // Interpreta un valor INI booleano tal y como lo hace PHP.
  function iniBool(v) {
    if (v === undefined || v === null) return null;
    const s = stripQuotes(String(v)).toLowerCase();
    if (['1', 'on', 'yes', 'true'].includes(s)) return true;
    if (['0', 'off', 'no', 'false', 'none', ''].includes(s)) return false;
    const n = Number(s);
    if (!Number.isNaN(n)) return n !== 0;
    return null;
  }

  // Convierte notación abreviada (K, M, G) a bytes. -1 => Infinity (sin límite).
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

  function fmtBytes(n) {
    if (n === Infinity) return 'sin límite (-1)';
    if (n === null) return 'desconocido';
    if (n % (1024 * 1024 * 1024) === 0) return n / (1024 * 1024 * 1024) + 'G';
    if (n % (1024 * 1024) === 0) return n / (1024 * 1024) + 'M';
    if (n % 1024 === 0) return n / 1024 + 'K';
    return n + ' bytes';
  }

  /* ------------------------------------------------------------------ */
  /* Parser línea a línea (conserva comentarios y orden)                 */
  /* ------------------------------------------------------------------ */

  // Separa "valor ; comentario" respetando comillas.
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
    let section = null; // nombre de la sección actual (null = ninguna / [PHP])
    lines.forEach((line, idx) => {
      const t = line.trim();
      const entry = { index: idx, raw: line, type: 'other', section };
      if (t === '') {
        entry.type = 'blank';
      } else if (t[0] === ';' || t[0] === '#') {
        entry.type = 'comment';
        // Detectar directivas comentadas: "; memory_limit = 128M" / ";memory_limit=128M"
        const m = /^[;#]\s*([A-Za-z_][\w.]*)\s*=\s*(.*)$/.exec(t);
        if (m && !/\s/.test(m[1])) {
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
          const rest = t.slice(eq + 1);
          const { value, comment } = splitValueComment(rest);
          entry.type = 'directive';
          entry.key = key.toLowerCase();
          entry.originalKey = key;
          entry.value = value;
          entry.comment = comment;
        }
      }
      entries.push(entry);
    });
    return { entries, eol, hadTrailingNewline: /\r?\n$/.test(text) };
  }

  // Devuelve la ÚLTIMA entrada efectiva de una directiva (PHP se queda con la última)
  // fuera de secciones [PATH=...] / [HOST=...], que son condicionales.
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
  /* Reglas                                                              */
  /* ------------------------------------------------------------------ */

  // Cada regla devuelve: { status: 'ok'|'change'|'add'|'info', suggested, reason }
  const RULES = [
    {
      key: 'session.upload_progress.enabled',
      cve: 'CVE-2026-109619',
      severity: 'critica',
      category: 'Mitigación recomendada por PHP',
      suggested: 'Off',
      scope: 'PHP_INI_PERDIR',
      why:
        'Desactiva el manejador de progreso de subida de sesión, cuyo estado global obsoleto es la vía ' +
        'confirmada de explotación de CVE-2026-109619. También reduce la superficie de CVE-2026-109618 ' +
        '(el deserializador del progreso de subida).',
      caveat:
        'Es PHP_INI_PERDIR: un .user.ini o un ini_set() de la aplicación NO deben usarse para esto. ' +
        'En PHP-FPM fíjalo también en el pool con php_admin_flag[session.upload_progress.enabled] = off ' +
        'y reinicia TODOS los procesos trabajadores. Mitigación parcial: no sustituye a la actualización.',
      check(ctx) {
        if (!ctx.present) return { status: 'add', detail: 'No está definida; el valor por defecto de PHP es On.' };
        const b = iniBool(ctx.value);
        if (b === false) return { status: 'ok' };
        return { status: 'change', detail: 'Está activada (' + ctx.value + ').' };
      },
    },
    {
      key: 'memory_limit',
      cve: 'CVE-2026-109618',
      severity: 'critica',
      category: 'Mitigación recomendada por PHP',
      suggested: '-1',
      scope: 'PHP_INI_ALL',
      why:
        'El disparador de CVE-2026-109618 es el aborto por agotamiento de memory_limit en mitad del ' +
        'análisis multipart. Con memory_limit = -1 PHP no aborta por ese límite y la ruta vulnerable no ' +
        'se alcanza por esa vía.',
      caveat:
        'Al retirar el límite, una sola petición puede consumir toda la memoria del servidor: acompáñalo ' +
        'SIEMPRE de un límite externo (cgroup memory.max, límite de contenedor o de systemd ' +
        'MemoryMax=). NO uses RLIMIT_AS / RLIMIT_DATA (ulimit -v/-d): provocan la misma ruta vulnerable. ' +
        'En PHP-FPM fíjalo con php_admin_value[memory_limit] = -1 para que la aplicación no pueda ' +
        'restaurarlo con ini_set(). Mitigación incompleta: no sustituye a la actualización.',
      check(ctx) {
        if (!ctx.present) return { status: 'add', detail: 'No está definida; el valor por defecto es 128M.' };
        const n = iniBytes(ctx.value);
        if (n === Infinity) return { status: 'ok' };
        return { status: 'change', detail: 'Límite actual: ' + ctx.value + ' (' + fmtBytes(n) + ').' };
      },
    },
    {
      key: 'post_max_size',
      cve: 'CVE-2026-109618',
      severity: 'alta',
      category: 'Límites de tamaño de petición',
      suggested: '8M',
      scope: 'PHP_INI_PERDIR',
      max: 8 * 1024 * 1024,
      why:
        'PHP recomienda un post_max_size bajo como medida provisional: reduce la cantidad de datos ' +
        'multipart que el analizador procesa antes de que pueda agotarse la memoria. Debe ' +
        'complementarse con límites de tamaño en el servidor web o proxy (client_max_body_size, ' +
        'LimitRequestBody), ya que una petición sin Content-Length utilizable puede esquivar la ' +
        'comprobación inicial de post_max_size.',
      caveat:
        'Ajusta el valor al máximo que realmente necesite tu aplicación; 8M es el valor por defecto de ' +
        'PHP. Debe ser mayor o igual que upload_max_filesize.',
      check(ctx) {
        if (!ctx.present) return { status: 'add', detail: 'No está definida (por defecto 8M). Conviene fijarla explícitamente.' };
        const n = iniBytes(ctx.value);
        if (n !== null && n !== Infinity && n <= this.max) return { status: 'ok' };
        return { status: 'change', detail: 'Valor actual ' + ctx.value + ' (' + fmtBytes(n) + ') supera el máximo recomendado de 8M.' };
      },
    },
    {
      key: 'upload_max_filesize',
      cve: 'CVE-2026-109618',
      severity: 'alta',
      category: 'Límites de tamaño de petición',
      suggested: '2M',
      scope: 'PHP_INI_PERDIR',
      max: 2 * 1024 * 1024,
      why:
        'Limita el tamaño de cada fichero subido y, con ello, el trabajo del analizador RFC 1867 por ' +
        'petición. Forma parte de los límites de tamaño de petición que PHP aconseja mientras no se ' +
        'pueda actualizar.',
      caveat:
        'Ajusta el valor a la necesidad real de la aplicación; 2M es el valor por defecto de PHP.',
      check(ctx) {
        if (!ctx.present) return { status: 'add', detail: 'No está definida (por defecto 2M). Conviene fijarla explícitamente.' };
        const n = iniBytes(ctx.value);
        if (n !== null && n !== Infinity && n <= this.max) return { status: 'ok' };
        return { status: 'change', detail: 'Valor actual ' + ctx.value + ' (' + fmtBytes(n) + ') supera el máximo recomendado de 2M.' };
      },
    },
    {
      key: 'max_file_uploads',
      cve: 'CVE-2026-109618',
      severity: 'alta',
      category: 'Límites de tamaño de petición',
      suggested: '20',
      scope: 'PHP_INI_SYSTEM',
      max: 20,
      why:
        'Las pruebas de concepto publicadas usan peticiones multipart con un gran número de campos de ' +
        'fichero (incluso vacíos) para forzar el agotamiento de memoria sin superar los límites de ' +
        'tamaño. Acotar el número de ficheros por petición reduce ese vector.',
      caveat: 'Baja el valor todo lo que permita la aplicación (p. ej. 5 si solo se sube un fichero a la vez).',
      check(ctx) {
        if (!ctx.present) return { status: 'add', detail: 'No está definida (por defecto 20). Conviene fijarla explícitamente y bajarla si es posible.' };
        const n = iniInt(ctx.value);
        if (n !== null && n >= 0 && n <= this.max) return { status: 'ok' };
        return { status: 'change', detail: 'Valor actual ' + ctx.value + ' supera el máximo recomendado de 20.' };
      },
    },
    {
      key: 'max_input_vars',
      cve: 'CVE-2026-109618',
      severity: 'media',
      category: 'Límites de tamaño de petición',
      suggested: '1000',
      scope: 'PHP_INI_PERDIR',
      max: 1000,
      why:
        'Limita el número de variables de entrada (campos del formulario multipart) que PHP acepta ' +
        'antes de abortar la petición, reduciendo el trabajo del analizador por petición.',
      caveat:
        'Medida de refuerzo general, no citada expresamente en el aviso oficial. 1000 es el valor por ' +
        'defecto de PHP; algunos CMS requieren valores mayores.',
      check(ctx) {
        if (!ctx.present) return { status: 'info', detail: 'No está definida (por defecto 1000). Se añade comentada como referencia.' };
        const n = iniInt(ctx.value);
        if (n !== null && n <= this.max) return { status: 'ok' };
        return { status: 'change', detail: 'Valor actual ' + ctx.value + ' supera el valor por defecto de 1000.' };
      },
    },
    {
      key: 'fatal_error_backtraces',
      cve: 'CVE-2026-109619',
      severity: 'alta',
      category: 'Mitigación recomendada por PHP (solo PHP 8.5)',
      suggested: 'Off',
      scope: 'PHP_INI_ALL',
      onlyVersions: ['8.5'],
      why:
        'En PHP 8.5 el backtrace generado en un error fatal es una de las vías confirmadas de ' +
        'CVE-2026-109619 (use-after-free del backtrace + confusión de tipos en OPcache). Desactivarlo ' +
        'cierra esa vía concreta.',
      caveat:
        'La directiva solo existe en PHP 8.5; en versiones anteriores se ignora (y genera un aviso en el ' +
        'arranque si se usa php_admin_value). Solo bloquea la vía del backtrace, no otras variantes.',
      check(ctx) {
        if (ctx.version && ctx.version !== '8.5' && ctx.version !== 'unknown') {
          return { status: 'skip', detail: 'Solo aplica a PHP 8.5.' };
        }
        if (!ctx.present) {
          return {
            status: ctx.version === '8.5' ? 'add' : 'info',
            detail: ctx.version === '8.5' ? 'No está definida; el valor por defecto en 8.5 es On.' : 'Solo aplica si usas PHP 8.5. Se añade comentada como referencia.',
          };
        }
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'change', detail: 'Está activada (' + ctx.value + ').' };
      },
    },
    {
      key: 'file_uploads',
      cve: 'CVE-2026-109618',
      severity: 'media',
      category: 'Reducción de superficie (opcional)',
      suggested: 'Off',
      scope: 'PHP_INI_SYSTEM',
      why:
        'Si la aplicación no necesita subir ficheros, desactivar file_uploads elimina el procesamiento ' +
        'de ficheros RFC 1867 (los campos de fichero se descartan).',
      caveat:
        'OPCIONAL: rompe cualquier subida de ficheros. PHP sigue analizando los campos normales de un ' +
        'formulario multipart, por lo que NO elimina por completo la ruta vulnerable. Evalúa si tu ' +
        'aplicación puede prescindir de las subidas durante la ventana de actualización.',
      check(ctx) {
        if (!ctx.present) return { status: 'info', detail: 'No está definida (por defecto On). Se añade comentada para que decidas.' };
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'info', detail: 'Las subidas están activadas. Se añade una sugerencia comentada para que decidas.' };
      },
    },
    {
      key: 'expose_php',
      cve: null,
      severity: 'baja',
      category: 'Endurecimiento general',
      suggested: 'Off',
      scope: 'PHP_INI_SYSTEM',
      why:
        'Oculta la cabecera X-Powered-By con la versión exacta de PHP. Los escáneres masivos de ' +
        'PHP2Shell la usan para localizar instalaciones vulnerables.',
      caveat: 'No mitiga la vulnerabilidad; solo dificulta la identificación de la versión.',
      check(ctx) {
        if (!ctx.present) return { status: 'add', detail: 'No está definida (por defecto On).' };
        if (iniBool(ctx.value) === false) return { status: 'ok' };
        return { status: 'change', detail: 'Está activada (' + ctx.value + ').' };
      },
    },
  ];

  /* ------------------------------------------------------------------ */
  /* Análisis                                                            */
  /* ------------------------------------------------------------------ */

  function analyze(text, options) {
    options = options || {};
    const version = options.version || 'unknown';
    const parsed = parse(text);
    const findings = [];

    for (const rule of RULES) {
      const entry = findDirective(parsed, rule.key);
      const conditional = findConditional(parsed, rule.key);
      const ctx = {
        present: !!entry,
        value: entry ? entry.value : undefined,
        version,
      };
      const r = rule.check(ctx);
      findings.push({
        key: rule.key,
        cve: rule.cve,
        severity: rule.severity,
        category: rule.category,
        suggested: rule.suggested,
        scope: rule.scope,
        why: rule.why,
        caveat: rule.caveat,
        status: r.status,
        detail: r.detail || '',
        line: entry ? entry.index + 1 : null,
        current: entry ? entry.value : null,
        conditionalLines: conditional.map((e) => e.index + 1),
        entry,
      });
    }

    const versionInfo = versionAdvice(version);
    return { parsed, findings, version, versionInfo };
  }

  function versionAdvice(version) {
    if (FIXED_VERSIONS[version]) {
      return {
        kind: 'supported',
        target: FIXED_VERSIONS[version],
        text:
          'Actualiza a PHP ' + FIXED_VERSIONS[version] + ' (o superior) cuanto antes. Las mitigaciones ' +
          'de php.ini son temporales y parciales.',
      };
    }
    if (['7.4', '8.0', '8.1'].includes(version)) {
      return {
        kind: 'eol',
        target: null,
        text:
          'PHP ' + version + ' está fuera de soporte: no hay versión oficial corregida. Existen parches ' +
          'mínimos en código fuente (desactivan por completo session.upload_progress) y muchas ' +
          'distribuciones (Debian, Ubuntu, RHEL) los incorporan en sus paquetes manteniendo el número ' +
          'de versión: comprueba el changelog del paquete, no php -v. Planifica la migración a ' +
          'PHP 8.2+ (8.2 solo recibe correcciones de seguridad hasta el 31/12/2026).',
      };
    }
    if (version === 'old') {
      return {
        kind: 'eol',
        target: null,
        text:
          'PHP 7.3 o anterior: sin ningún parche disponible. Aplica las mitigaciones, aísla el servicio ' +
          'y migra urgentemente a PHP 8.2 o superior (8.3 o 8.4 recomendadas).',
      };
    }
    return {
      kind: 'unknown',
      target: null,
      text:
        'Versiones corregidas: 8.5.12, 8.4.27, 8.3.36 y 8.2.35. Para 7.4, 8.0 y 8.1 solo hay parches ' +
        'retroportados en fuente o de distribución; versiones anteriores no tienen corrección.',
    };
  }

  /* ------------------------------------------------------------------ */
  /* Generación del php.ini anotado                                      */
  /* ------------------------------------------------------------------ */

  const SEV_LABEL = { critica: 'CRÍTICA', alta: 'ALTA', media: 'MEDIA', baja: 'BAJA' };

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

  function commentBlock(f, action) {
    const lines = [];
    lines.push(';; --- PHP2Shell: ' + action + ' [' + SEV_LABEL[f.severity] + '] ---');
    if (f.cve) lines.push(';; ' + f.cve + ' (' + CVES[f.cve].ghsa + ')');
    if (f.detail) lines.push(...wrap('Motivo: ' + f.detail, 76, ';; '));
    lines.push(...wrap(f.why, 76, ';; '));
    lines.push(...wrap('Atención: ' + f.caveat, 76, ';; '));
    return lines;
  }

  function annotate(text, options) {
    const result = analyze(text, options);
    const { parsed, findings, version, versionInfo } = result;
    const eol = parsed.eol;
    const out = [];
    const today = (options && options.date) || new Date().toISOString().slice(0, 10);

    // Cabecera
    out.push(';; ==========================================================================');
    out.push(';; php.ini anotado automáticamente - mitigaciones PHP2Shell');
    out.push(';; CVE-2026-109618 / CVE-2026-109619 (aviso INCIBE-CERT 21/10/2026, crítica)');
    out.push(';; Generado el ' + today + ' - versión de PHP indicada: ' + (version === 'unknown' ? 'no indicada' : version));
    out.push(';;');
    out.push(...wrap(versionInfo.text, 76, ';; '));
    out.push(';;');
    out.push(';; Estas mitigaciones son TEMPORALES y PARCIALES. La única corrección completa es');
    out.push(';; actualizar PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) y reiniciar PHP-FPM / Apache.');
    out.push(';; Las líneas originales modificadas se conservan comentadas con el prefijo ";;OLD".');
    out.push(';; Revisa cada cambio antes de aplicarlo en producción.');
    out.push(';; ==========================================================================');
    out.push('');

    // Mapa de índice de línea -> finding (para sustituir in situ)
    const byLine = new Map();
    for (const f of findings) {
      if (f.entry && (f.status === 'change' || f.status === 'ok' || (f.status === 'info' && f.entry))) byLine.set(f.entry.index, f);
    }

    const firstCond = parsed.entries.findIndex((e) => e.type === 'section' && isConditionalSection(e.name));
    let condInsertPos = -1;

    // Directivas ausentes cuya versión comentada existe en el fichero (p. ej.
    // ";session.upload_progress.enabled = On"): se insertan justo debajo de ella.
    const pending = findings.filter((f) => !f.entry && (f.status === 'add' || f.status === 'info'));
    const placed = new Set();

    function addedBlock(f) {
      const block = [];
      if (f.status === 'add') {
        block.push(...commentBlock(f, 'DIRECTIVA AÑADIDA'));
        block.push(f.key + ' = ' + f.suggested);
      } else {
        block.push(...commentBlock(f, 'SUGERENCIA OPCIONAL (comentada)'));
        block.push(';' + f.key + ' = ' + f.suggested);
      }
      block.push(';; --- fin PHP2Shell ---');
      return block;
    }

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
        out.push(e.raw + ' ;; PHP2Shell: OK, valor ya seguro');
      } else if (f.status === 'change') {
        out.push(...commentBlock(f, 'CAMBIO SUGERIDO'));
        out.push(';;OLD ' + e.raw);
        out.push(e.originalKey + ' = ' + f.suggested);
        out.push(';; --- fin PHP2Shell ---');
      } else if (f.status === 'info') {
        out.push(...commentBlock(f, 'REVISIÓN OPCIONAL (sin cambios)'));
        out.push(';; Sugerencia si procede: ' + e.originalKey + ' = ' + f.suggested);
        out.push(e.raw);
        out.push(';; --- fin PHP2Shell ---');
      }
    }

    // Bloque de directivas ausentes
    const toAdd = pending.filter((f) => !placed.has(f.key));
    if (toAdd.length) {
      const block = [];
      block.push('');
      block.push(';; ==========================================================================');
      block.push(';; PHP2Shell: directivas NO presentes en el fichero original');
      block.push(';; Añadidas al final: en php.ini la última aparición de una directiva prevalece.');
      block.push(';; ==========================================================================');
      for (const f of toAdd) {
        block.push('');
        block.push(...addedBlock(f));
      }

      // Si el fichero termina dentro de una sección [PATH=]/[HOST=], insertar antes
      // de la primera sección condicional para no limitar el alcance de las directivas.
      const lastSection = [...parsed.entries].reverse().find((e) => e.type === 'section');
      if (lastSection && isConditionalSection(lastSection.name) && condInsertPos >= 0) {
        out.splice(condInsertPos, 0, ...block, '');
      } else {
        out.push(...block);
      }
    }

    // Advertencia sobre secciones condicionales que redefinen directivas
    const cond = findings.filter((f) => f.conditionalLines.length);
    if (cond.length) {
      out.push('');
      out.push(';; ATENCIÓN PHP2Shell: las siguientes directivas también se redefinen dentro de secciones');
      out.push(';; [PATH=...] / [HOST=...] y prevalecen para esos hosts/rutas. Revísalas manualmente:');
      for (const f of cond) out.push(';;   ' + f.key + ' en las líneas ' + f.conditionalLines.join(', '));
    }

    out.push('');
    out.push(';; Recordatorio final PHP2Shell: tras aplicar los cambios reinicia TODOS los procesos');
    out.push(';; (systemctl restart php-fpm / apache2) y verifica con php --ini y php -i.');

    let output = out.join(eol);
    if (!output.endsWith(eol)) output += eol;
    return { output, result };
  }

  return {
    parse,
    analyze,
    annotate,
    iniBool,
    iniBytes,
    iniInt,
    fmtBytes,
    RULES,
    CVES,
    FIXED_VERSIONS,
    SEV_LABEL,
  };
});
