/* Textos en español para el analizador y la interfaz. */
(function (root, factory) {
  const data = factory();
  if (typeof module === 'object' && module.exports) module.exports = data;
  else root.PhpIniAnalyzer.registerLocale('es', data);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return {
    code: 'es',
    severity: { critica: 'CRÍTICA', alta: 'ALTA', media: 'MEDIA', baja: 'BAJA' },
    status: { ok: 'OK', change: 'Cambiar', add: 'Añadir', info: 'Revisar', skip: 'No aplica' },
    bytes: { unlimited: 'sin límite (-1)', unknown: 'desconocido' },
    ui: {
      noFile: 'Ningún fichero seleccionado',
      sampleLoaded: 'Ejemplo cargado (php.ini-production)',
      emptyAlert: 'Carga o pega primero el contenido de un php.ini.',
      copied: 'Copiado ✓',
      copy: 'Copiar al portapapeles',
      clipboardError: 'No se pudo acceder al portapapeles; copia el texto de la vista previa.',
      phpVersion: 'Versión de PHP:',
      notDefined: 'no definida',
      empty: '(vacío)',
      alsoConditional: 'También definida en secciones [PATH=]/[HOST=]',
      vulnerabilities: 'Vulnerabilidades',
      directives: 'Directivas analizadas',
      phpAdvisory: 'Aviso de PHP:',
      caution: 'Atención:',
      scope: 'Ámbito:',
      downloadSuffix: '.php2shell-anotado.ini',
    },
    cves: {
      'CVE-2026-109618': {
        title: 'Corrupción de memoria tras agotar memory_limit durante el análisis multipart (RFC 1867)',
        summary:
          'Una petición multipart/form-data manipulada agota memory_limit mientras PHP todavía está ' +
          'inicializando los datos de la petición. El aborto deja estructuras parcialmente inicializadas ' +
          'que la limpieza final trata como válidas (use-after-free / puntero sin inicializar), lo que ' +
          'permite ejecución remota de código sin autenticación.',
      },
      'CVE-2026-109619': {
        title: 'Estado global obsoleto reutilizado tras un error fatal (session.upload_progress / backtrace)',
        summary:
          'Tras un error fatal, parte del estado global de la petición (manejador de progreso de subida ' +
          'de sesión, backtrace del error fatal) sobrevive a la liberación de su memoria y la siguiente ' +
          'petición atendida por el mismo proceso trabajador la reutiliza. Permite ejecución remota de ' +
          'código sin autenticación.',
      },
    },
    version: {
      supported: 'Actualiza a PHP {target} (o superior) cuanto antes. Las mitigaciones de php.ini son temporales y parciales.',
      eol:
        'PHP {version} está fuera de soporte: no hay versión oficial corregida. Existen parches mínimos en ' +
        'código fuente (desactivan por completo session.upload_progress) y muchas distribuciones (Debian, ' +
        'Ubuntu, RHEL) los incorporan en sus paquetes manteniendo el número de versión: comprueba el ' +
        'changelog del paquete, no php -v. Planifica la migración a PHP 8.2+ (8.2 solo recibe correcciones ' +
        'de seguridad hasta el 31/12/2026).',
      old:
        'PHP 7.3 o anterior: sin ningún parche disponible. Aplica las mitigaciones, aísla el servicio y ' +
        'migra urgentemente a PHP 8.2 o superior (8.3 o 8.4 recomendadas).',
      unknown:
        'Versiones corregidas: 8.5.12, 8.4.27, 8.3.36 y 8.2.35. Para 7.4, 8.0 y 8.1 solo hay parches ' +
        'retroportados en fuente o de distribución; versiones anteriores no tienen corrección.',
    },
    annotate: {
      header: [
        'php.ini anotado automáticamente - mitigaciones PHP2Shell',
        'CVE-2026-109618 / CVE-2026-109619 (aviso INCIBE-CERT 21/10/2026, crítica)',
      ],
      generated: 'Generado el {date} - versión de PHP indicada: {version}',
      versionNotGiven: 'no indicada',
      disclaimer: [
        'Estas mitigaciones son TEMPORALES y PARCIALES. La única corrección completa es',
        'actualizar PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) y reiniciar PHP-FPM / Apache.',
        'Las líneas originales modificadas se conservan comentadas con el prefijo ";;OLD".',
        'Revisa cada cambio antes de aplicarlo en producción.',
      ],
      reason: 'Motivo:',
      caution: 'Atención:',
      actionChange: 'CAMBIO SUGERIDO',
      actionAdded: 'DIRECTIVA AÑADIDA',
      actionOptional: 'SUGERENCIA OPCIONAL (comentada)',
      actionReview: 'REVISIÓN OPCIONAL (sin cambios)',
      suggestionIfApplicable: 'Sugerencia si procede:',
      okInline: ';; PHP2Shell: OK, valor ya seguro',
      end: ';; --- fin PHP2Shell ---',
      missingHeader: [
        'PHP2Shell: directivas NO presentes en el fichero original',
        'Añadidas al final: en php.ini la última aparición de una directiva prevalece.',
      ],
      conditionalWarning: [
        'ATENCIÓN PHP2Shell: las siguientes directivas también se redefinen dentro de secciones',
        '[PATH=...] / [HOST=...] y prevalecen para esos hosts/rutas. Revísalas manualmente:',
      ],
      conditionalLine: '{key} en las líneas {lines}',
      footer: [
        'Recordatorio final PHP2Shell: tras aplicar los cambios reinicia TODOS los procesos',
        '(systemctl restart php-fpm / apache2) y verifica con php --ini y php -i.',
      ],
    },
    rules: {
      'session.upload_progress.enabled': {
        category: 'Mitigación recomendada por PHP',
        why:
          'Desactiva el manejador de progreso de subida de sesión, cuyo estado global obsoleto es la vía ' +
          'confirmada de explotación de CVE-2026-109619. También reduce la superficie de CVE-2026-109618 ' +
          '(el deserializador del progreso de subida).',
        caveat:
          'Es PHP_INI_PERDIR: un .user.ini o un ini_set() de la aplicación NO deben usarse para esto. ' +
          'En PHP-FPM fíjalo también en el pool con php_admin_flag[session.upload_progress.enabled] = off ' +
          'y reinicia TODOS los procesos trabajadores. Mitigación parcial: no sustituye a la actualización.',
        details: { add: 'No está definida; el valor por defecto de PHP es On.', change: 'Está activada ({value}).' },
      },
      memory_limit: {
        category: 'Mitigación recomendada por PHP',
        why:
          'El disparador de CVE-2026-109618 es el aborto por agotamiento de memory_limit en mitad del ' +
          'análisis multipart. Con memory_limit = -1 PHP no aborta por ese límite y la ruta vulnerable no ' +
          'se alcanza por esa vía.',
        caveat:
          'Al retirar el límite, una sola petición puede consumir toda la memoria del servidor: acompáñalo ' +
          'SIEMPRE de un límite externo (cgroup memory.max, límite de contenedor o de systemd MemoryMax=). ' +
          'NO uses RLIMIT_AS / RLIMIT_DATA (ulimit -v/-d): provocan la misma ruta vulnerable. En PHP-FPM ' +
          'fíjalo con php_admin_value[memory_limit] = -1 para que la aplicación no pueda restaurarlo con ' +
          'ini_set(). Mitigación incompleta: no sustituye a la actualización.',
        details: { add: 'No está definida; el valor por defecto es 128M.', change: 'Límite actual: {value} ({bytes}).' },
      },
      post_max_size: {
        category: 'Límites de tamaño de petición',
        why:
          'PHP recomienda un post_max_size bajo como medida provisional: reduce la cantidad de datos ' +
          'multipart que el analizador procesa antes de que pueda agotarse la memoria. Debe complementarse ' +
          'con límites de tamaño en el servidor web o proxy (client_max_body_size, LimitRequestBody), ya ' +
          'que una petición sin Content-Length utilizable puede esquivar la comprobación inicial de post_max_size.',
        caveat: 'Ajusta el valor al máximo que realmente necesite tu aplicación; 8M es el valor por defecto de PHP. Debe ser mayor o igual que upload_max_filesize.',
        details: { add: 'No está definida (por defecto 8M). Conviene fijarla explícitamente.', change: 'Valor actual {value} ({bytes}) supera el máximo recomendado de 8M.' },
      },
      upload_max_filesize: {
        category: 'Límites de tamaño de petición',
        why:
          'Limita el tamaño de cada fichero subido y, con ello, el trabajo del analizador RFC 1867 por ' +
          'petición. Forma parte de los límites de tamaño de petición que PHP aconseja mientras no se pueda actualizar.',
        caveat: 'Ajusta el valor a la necesidad real de la aplicación; 2M es el valor por defecto de PHP.',
        details: { add: 'No está definida (por defecto 2M). Conviene fijarla explícitamente.', change: 'Valor actual {value} ({bytes}) supera el máximo recomendado de 2M.' },
      },
      max_file_uploads: {
        category: 'Límites de tamaño de petición',
        why:
          'Las pruebas de concepto publicadas usan peticiones multipart con un gran número de campos de ' +
          'fichero (incluso vacíos) para forzar el agotamiento de memoria sin superar los límites de tamaño. ' +
          'Acotar el número de ficheros por petición reduce ese vector.',
        caveat: 'Baja el valor todo lo que permita la aplicación (p. ej. 5 si solo se sube un fichero a la vez).',
        details: { add: 'No está definida (por defecto 20). Conviene fijarla explícitamente y bajarla si es posible.', change: 'Valor actual {value} supera el máximo recomendado de 20.' },
      },
      max_input_vars: {
        category: 'Límites de tamaño de petición',
        why:
          'Limita el número de variables de entrada (campos del formulario multipart) que PHP acepta antes ' +
          'de abortar la petición, reduciendo el trabajo del analizador por petición.',
        caveat: 'Medida de refuerzo general, no citada expresamente en el aviso oficial. 1000 es el valor por defecto de PHP; algunos CMS requieren valores mayores.',
        details: { info: 'No está definida (por defecto 1000). Se añade comentada como referencia.', change: 'Valor actual {value} supera el valor por defecto de 1000.' },
      },
      fatal_error_backtraces: {
        category: 'Mitigación recomendada por PHP (solo PHP 8.5)',
        why:
          'En PHP 8.5 el backtrace generado en un error fatal es una de las vías confirmadas de ' +
          'CVE-2026-109619 (use-after-free del backtrace + confusión de tipos en OPcache). Desactivarlo ' +
          'cierra esa vía concreta.',
        caveat:
          'La directiva solo existe en PHP 8.5; en versiones anteriores se ignora (y genera un aviso en el ' +
          'arranque si se usa php_admin_value). Solo bloquea la vía del backtrace, no otras variantes.',
        details: {
          skip: 'Solo aplica a PHP 8.5.',
          add: 'No está definida; el valor por defecto en 8.5 es On.',
          info: 'Solo aplica si usas PHP 8.5. Se añade comentada como referencia.',
          change: 'Está activada ({value}).',
        },
      },
      file_uploads: {
        category: 'Reducción de superficie (opcional)',
        why:
          'Si la aplicación no necesita subir ficheros, desactivar file_uploads elimina el procesamiento ' +
          'de ficheros RFC 1867 (los campos de fichero se descartan).',
        caveat:
          'OPCIONAL: rompe cualquier subida de ficheros. PHP sigue analizando los campos normales de un ' +
          'formulario multipart, por lo que NO elimina por completo la ruta vulnerable. Evalúa si tu ' +
          'aplicación puede prescindir de las subidas durante la ventana de actualización.',
        details: {
          infoAbsent: 'No está definida (por defecto On). Se añade comentada para que decidas.',
          infoOn: 'Las subidas están activadas. Se añade una sugerencia comentada para que decidas.',
        },
      },
      expose_php: {
        category: 'Endurecimiento general',
        why:
          'Oculta la cabecera X-Powered-By con la versión exacta de PHP. Los escáneres masivos de ' +
          'PHP2Shell la usan para localizar instalaciones vulnerables.',
        caveat: 'No mitiga la vulnerabilidad; solo dificulta la identificación de la versión.',
        details: { add: 'No está definida (por defecto On).', change: 'Está activada ({value}).' },
      },
    },
  };
});
