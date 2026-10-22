# Analizador de `php.ini` frente a PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

Aplicación web estática, pensada para desplegarse en **GitHub Pages**, que analiza un
fichero `php.ini` y genera una copia **anotada con comentarios** que explican los cambios
sugeridos para mitigar las vulnerabilidades descritas en el aviso de INCIBE-CERT
[«Múltiples vulnerabilidades en PHP»](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-php)
(21/10/2026, importancia **crítica**), mientras se planifica y ejecuta la actualización de PHP.

**Todo se ejecuta en el navegador, en JavaScript puro.** El `php.ini` no se envía a ningún
servidor: la página se puede abrir incluso sin conexión una vez cargada.

Web publicada: <https://ojgarciab.github.io/2026-10-21-php-vulnerable/>, disponible en
[español](https://ojgarciab.github.io/2026-10-21-php-vulnerable/es/),
[inglés](https://ojgarciab.github.io/2026-10-21-php-vulnerable/en/),
[francés](https://ojgarciab.github.io/2026-10-21-php-vulnerable/fr/),
[italiano](https://ojgarciab.github.io/2026-10-21-php-vulnerable/it/),
[alemán](https://ojgarciab.github.io/2026-10-21-php-vulnerable/de/) y
[portugués](https://ojgarciab.github.io/2026-10-21-php-vulnerable/pt/).

## Propósito

El aviso de INCIBE-CERT recoge dos vulnerabilidades de ejecución remota de código sin
autenticación en el intérprete de PHP, bautizadas por la comunidad como **PHP2Shell**:

| CVE | Aviso de PHP | Descripción | CVSS v4 |
|-----|--------------|-------------|---------|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | Agotamiento de `memory_limit` durante el análisis de peticiones *multipart* (RFC 1867). El aborto deja estructuras de la petición parcialmente inicializadas que la limpieza final trata como válidas (corrupción de memoria / *use-after-free*). | 9.2 |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | Estado global obsoleto que sobrevive a un error fatal (manejador `session.upload_progress`, *backtrace* del error fatal) y es reutilizado por la siguiente petición atendida por el mismo proceso trabajador. | 9.2 |

Ambas afectan al núcleo del intérprete, por lo que cualquier aplicación PHP expuesta
(WordPress, Drupal, Joomla, aplicaciones a medida) es vulnerable con independencia de su código.
Se han demostrado ejecuciones de código previas a la autenticación y, según varios
proveedores, hay intentos de explotación en Internet desde el mismo día de la publicación.

**La única corrección completa es actualizar PHP** a una versión corregida y reiniciar todos
los procesos (PHP-FPM, Apache `mod_php`, etc.):

| Rama | Versión corregida |
|------|-------------------|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 (esta rama solo recibe correcciones de seguridad hasta el 31/12/2026) |
| 8.1, 8.0, 7.4 | Sin versión oficial. Existen parches mínimos en código fuente (que desactivan por completo `session.upload_progress`) y las distribuciones (Debian, Ubuntu, RHEL, AlmaLinux…) los retroportan manteniendo el número de versión: compruébalo en el *changelog* del paquete, no con `php -v`. |
| 7.3 y anteriores | Sin parche. Mitigar, aislar y migrar urgentemente. |

Mientras la actualización no sea posible (ventanas de mantenimiento, dependencias de
aplicaciones heredadas, ramas sin soporte), esta herramienta ayuda a aplicar de forma
documentada las **mitigaciones temporales y parciales** recomendadas en los avisos.

## Qué hace la web

1. Permite **arrastrar, seleccionar o pegar** un `php.ini` (o cargar un ejemplo basado en
   `php.ini-production`).
2. Opcionalmente, indicar la **versión de PHP** del servidor para adaptar las recomendaciones
   (por ejemplo, `fatal_error_backtraces` solo existe en PHP 8.5) y mostrar la versión objetivo.
3. Analiza las directivas relevantes respetando la semántica de `php.ini`: la **última aparición
   prevalece**, los valores pueden ir entre comillas, admiten notación abreviada (`128M`, `2G`) y
   los valores booleanos (`On`/`Off`/`1`/`0`/`yes`/`no`…). Las secciones condicionales
   `[PATH=…]` / `[HOST=…]` se detectan y se avisa de ellas, pero no se modifican.
4. Muestra una **tabla de hallazgos** (OK / Cambiar / Añadir / Revisar / No aplica) con la línea,
   el valor actual, el valor sugerido, el CVE asociado y la severidad.
5. Genera y permite **descargar un `php.ini` anotado** que:
   - conserva íntegramente el fichero original (orden, comentarios, saltos de línea CRLF/LF);
   - antepone a cada cambio un bloque de comentarios `;;` con el CVE, el motivo y las precauciones;
   - deja la línea original comentada con el prefijo `;;OLD` y escribe debajo la línea sugerida;
   - inserta las directivas ausentes debajo de su versión comentada si existe (p. ej.
     `;session.upload_progress.enabled = On`) o, si no, en un bloque al final del fichero (antes
     de cualquier sección `[PATH=…]`/`[HOST=…]` para no limitar su alcance);
   - marca las directivas opcionales como sugerencias comentadas para que el administrador decida.

El fichero resultante es un `php.ini` válido. Aun así, **revísalo antes de aplicarlo en
producción** y reinicia todos los procesos después.

## Mitigaciones que cubre

| Directiva | Valor sugerido | Severidad | CVE | Observaciones |
|-----------|----------------|-----------|-----|---------------|
| `session.upload_progress.enabled` | `Off` | Crítica | CVE-2026-109619 | Mitigación temporal recomendada por PHP. Es `PHP_INI_PERDIR`: no confiar en `.user.ini` ni `ini_set()`. En PHP-FPM fijarla además en el *pool* con `php_admin_flag[...] = off` y reiniciar todos los trabajadores. |
| `memory_limit` | `-1` | Crítica | CVE-2026-109618 | Evita el aborto por `memory_limit` que dispara la vulnerabilidad. Debe acompañarse **siempre** de un límite externo (cgroup `memory.max`, límite del contenedor o `MemoryMax=` de systemd). **No** usar `RLIMIT_AS`/`RLIMIT_DATA` (`ulimit -v/-d`): provocan la misma ruta vulnerable. En PHP-FPM usar `php_admin_value[memory_limit] = -1` para que la aplicación no pueda restaurarlo. |
| `post_max_size` | `≤ 8M` | Alta | CVE-2026-109618 | Reduce los datos *multipart* procesados por petición. Complementar con límites en el servidor web/proxy (`client_max_body_size`, `LimitRequestBody`): una petición sin `Content-Length` utilizable puede esquivar la comprobación inicial. |
| `upload_max_filesize` | `≤ 2M` | Alta | CVE-2026-109618 | Límite por fichero subido; ajustar a la necesidad real. |
| `max_file_uploads` | `≤ 20` | Alta | CVE-2026-109618 | Las pruebas de concepto usan muchos campos de fichero (incluso vacíos) para agotar la memoria sin superar los límites de tamaño. Bajarlo todo lo posible. |
| `max_input_vars` | `≤ 1000` | Media | CVE-2026-109618 | Refuerzo general (no citado expresamente en los avisos): limita el número de campos aceptados por petición. |
| `fatal_error_backtraces` | `Off` | Alta | CVE-2026-109619 | Solo PHP 8.5. Cierra la vía confirmada del *backtrace* de error fatal (UAF + confusión de tipos en OPcache). |
| `file_uploads` | `Off` | Media (opcional) | CVE-2026-109618 | Solo si la aplicación no necesita subidas. PHP sigue analizando los campos normales de un formulario *multipart*, así que no elimina por completo la ruta vulnerable. Se añade comentada. |
| `expose_php` | `Off` | Baja | — | Endurecimiento: oculta la cabecera `X-Powered-By` que los escáneres usan para localizar versiones vulnerables. No mitiga la vulnerabilidad. |

### Lo que la web NO puede cubrir (y conviene hacer igualmente)

- **Actualizar PHP** y reiniciar PHP-FPM / Apache; verificar la versión en ejecución (`php -v`,
  `php --ini`, `phpinfo()`) y, en distribuciones que retroportan, el *changelog* del paquete.
- Configuración del *pool* de PHP-FPM (`php_admin_value`, `php_admin_flag`, `pm.max_requests`
  bajo para reducir la ventana de reutilización de un trabajador contaminado).
- Límites de tamaño de petición en Nginx/Apache/proxy y reglas de WAF para *multipart* anómalos.
- Fuentes de configuración adicionales: `conf.d/*.ini`, `.user.ini`, `.htaccess` (`php_value`),
  `ini_set()` en la aplicación. La herramienta solo analiza el fichero que se le entrega.

## Despliegue en GitHub Pages

El sitio es completamente estático y vive en la carpeta `docs/`. Hay una página HTML por idioma
(`docs/es/`, `docs/en/`, `docs/fr/`, `docs/it/`, `docs/de/` y `docs/pt/`), generadas todas desde una
plantilla única por `tools/build-pages.py`, y comparten la hoja de estilos y el JavaScript de
`docs/css` y `docs/js`. La raíz `docs/index.html` redirige al idioma guardado en el navegador o,
si no lo hay, al del propio navegador (español por defecto); cada página enlaza a las demás con un
selector de idioma y etiquetas `hreflang`.
GitHub Pages está configurado en *Settings → Pages* con *Deploy from a branch* y la carpeta
`/docs`, de modo que cada *push* a la rama publicada actualiza la web. El fichero
`docs/.nojekyll` evita el procesado de Jekyll. Las pruebas se ejecutan en cada *push* mediante
`.github/workflows/test.yml`.

Para probar en local basta con un servidor estático, por ejemplo:

```bash
python3 -m http.server 8080 --directory docs   # o: npm start
```

## Estructura y pruebas

```
docs/index.html          Redirección al idioma del usuario
docs/<idioma>/index.html Interfaz en cada idioma (es, en, fr, it, de, pt), generada por tools/build-pages.py
docs/css/style.css       Estilos comunes (modo claro/oscuro, adaptable a móvil)
docs/js/analyzer.js      Parser de php.ini, reglas y generador del fichero anotado (sin dependencias)
docs/js/locale-<idioma>.js Textos de cada idioma (interfaz, explicaciones y comentarios del fichero generado)
tools/build-pages.py     Plantilla HTML y textos estáticos de cada idioma; regenera docs/<idioma>/index.html
docs/js/app.js           Lógica de la interfaz común (carga, tabla de resultados, descarga)
docs/js/sample.js        Extracto de php.ini-production para pruebas
test/analyzer.test.js    Pruebas con el módulo `node:assert`
```

```bash
node test/analyzer.test.js   # o: npm test
```

Para añadir o ajustar una comprobación basta con editar la lista `RULES` de `docs/js/analyzer.js`
(directiva, valor sugerido, severidad, CVE y una función `check()` que devuelve `ok`, `change`,
`add`, `info` o `skip`) y añadir sus textos en cada `docs/js/locale-*.js` (las pruebas comprueban que
todos los idiomas tienen las mismas claves). Para añadir un idioma: copiar `docs/js/locale-es.js` con el
nuevo código, añadir su entrada en `LANGS` de `tools/build-pages.py`, ejecutar el script (regenera todas
las páginas con el selector actualizado) y añadir el código a la lista `supported` de `docs/index.html`.

## Fuentes

- INCIBE-CERT, [Múltiples vulnerabilidades en PHP](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-php) (21/10/2026).
- Avisos de seguridad de PHP: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618) y [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619).
- PHP Foundation, [Today's PHP Security Release, and How We're Strengthening PHP Security](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/).
- Wiz, [PHP2Shell: AI uncovers critical RCE vulnerabilities](https://www.wiz.io/blog/php2shell-php-rce).
- watchTowr, [PHP RCE FAQ: PHP2Shell](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/).
- Red Hat, [CVE-2026-109618](https://access.redhat.com/security/cve/cve-2026-109618).
- Cloudflare, [Cloudflare deploys protections against php2shell vulnerability](https://blog.cloudflare.com/php-vulnerabilities-waf-protection).
- Sansec, [PHP2Shell: Critical PHP RCE](https://sansec.io/research/php2shell).
- Qualys, [PHP2Shell: PHP Patches Two Critical RCE Vulnerabilities](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities).
- Mattias Geniar, [PHP CVE-2026-109618 and CVE-2026-109619: early mitigation steps](https://ma.ttias.be/php-cve-2026-109618-early-mitigation/) y [how to apply the patches](https://ma.ttias.be/php-cve-2026-109618-patch/).
- NCSC (Reino Unido), [Critical security issue affecting PHP](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php).

## Licencia

GPL-3.0. Véase [LICENSE](LICENSE).

> Herramienta de apoyo sin garantías. Las mitigaciones de `php.ini` son parciales y temporales;
> la única corrección completa es actualizar PHP.
