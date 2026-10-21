/* English texts for the analyzer and the user interface. */
(function (root, factory) {
  const data = factory();
  if (typeof module === 'object' && module.exports) module.exports = data;
  else root.PhpIniAnalyzer.registerLocale('en', data);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return {
    code: 'en',
    severity: { critica: 'CRITICAL', alta: 'HIGH', media: 'MEDIUM', baja: 'LOW' },
    status: { ok: 'OK', change: 'Change', add: 'Add', info: 'Review', skip: 'N/A' },
    bytes: { unlimited: 'unlimited (-1)', unknown: 'unknown' },
    ui: {
      noFile: 'No file selected',
      sampleLoaded: 'Sample loaded (php.ini-production)',
      emptyAlert: 'Load or paste the contents of a php.ini first.',
      copied: 'Copied ✓',
      copy: 'Copy to clipboard',
      clipboardError: 'Clipboard access failed; copy the text from the preview instead.',
      phpVersion: 'PHP version:',
      notDefined: 'not set',
      empty: '(empty)',
      alsoConditional: 'Also set inside [PATH=]/[HOST=] sections',
      vulnerabilities: 'Vulnerabilities',
      directives: 'Directives checked',
      phpAdvisory: 'PHP advisory:',
      caution: 'Caution:',
      scope: 'Scope:',
      downloadSuffix: '.php2shell-annotated.ini',
    },
    cves: {
      'CVE-2026-109618': {
        title: 'Memory corruption after memory_limit exhaustion during multipart (RFC 1867) parsing',
        summary:
          'A crafted multipart/form-data request exhausts memory_limit while PHP is still initialising ' +
          'the request data. The abort leaves partially initialised structures that the final cleanup ' +
          'treats as valid (use-after-free / uninitialised pointer), allowing unauthenticated remote code execution.',
      },
      'CVE-2026-109619': {
        title: 'Stale global state reused after a fatal error (session.upload_progress / backtrace)',
        summary:
          'After a fatal error, part of the request\'s global state (session upload-progress handler, ' +
          'fatal-error backtrace) outlives the memory that held it, and the next request served by the ' +
          'same worker process reuses it. Allows unauthenticated remote code execution.',
      },
    },
    version: {
      supported: 'Upgrade to PHP {target} (or later) as soon as possible. The php.ini mitigations are temporary and partial.',
      eol:
        'PHP {version} is end-of-life: there is no official fixed release. Minimal source patches exist ' +
        '(they disable session.upload_progress entirely) and many distributions (Debian, Ubuntu, RHEL) ' +
        'backport them while keeping the version number: check the package changelog, not php -v. ' +
        'Plan the migration to PHP 8.2+ (8.2 only receives security fixes until 2026-12-31).',
      old:
        'PHP 7.3 or earlier: no patch available at all. Apply the mitigations, isolate the service and ' +
        'migrate urgently to PHP 8.2 or later (8.3 or 8.4 recommended).',
      unknown:
        'Fixed releases: 8.5.12, 8.4.27, 8.3.36 and 8.2.35. For 7.4, 8.0 and 8.1 only source or ' +
        'distribution backports exist; earlier versions have no fix.',
    },
    annotate: {
      header: [
        'php.ini annotated automatically - PHP2Shell mitigations',
        'CVE-2026-109618 / CVE-2026-109619 (INCIBE-CERT advisory 2026-10-21, critical)',
      ],
      generated: 'Generated on {date} - PHP version given: {version}',
      versionNotGiven: 'not given',
      disclaimer: [
        'These mitigations are TEMPORARY and PARTIAL. The only complete fix is to upgrade',
        'PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) and restart PHP-FPM / Apache.',
        'Modified original lines are kept commented out with the ";;OLD" prefix.',
        'Review every change before applying it in production.',
      ],
      reason: 'Reason:',
      caution: 'Caution:',
      actionChange: 'SUGGESTED CHANGE',
      actionAdded: 'DIRECTIVE ADDED',
      actionOptional: 'OPTIONAL SUGGESTION (commented out)',
      actionReview: 'OPTIONAL REVIEW (no change)',
      suggestionIfApplicable: 'Suggestion if applicable:',
      okInline: ';; PHP2Shell: OK, value already safe',
      end: ';; --- end PHP2Shell ---',
      missingHeader: [
        'PHP2Shell: directives NOT present in the original file',
        'Appended at the end: in php.ini the last occurrence of a directive wins.',
      ],
      conditionalWarning: [
        'PHP2Shell WARNING: the following directives are also redefined inside [PATH=...] /',
        '[HOST=...] sections and take precedence for those hosts/paths. Review them manually:',
      ],
      conditionalLine: '{key} on lines {lines}',
      footer: [
        'Final PHP2Shell reminder: after applying the changes restart ALL processes',
        '(systemctl restart php-fpm / apache2) and verify with php --ini and php -i.',
      ],
    },
    rules: {
      'session.upload_progress.enabled': {
        category: 'Mitigation recommended by PHP',
        why:
          'Disables the session upload-progress handler, whose stale global state is the confirmed ' +
          'exploitation path for CVE-2026-109619. It also reduces the attack surface of CVE-2026-109618 ' +
          '(the upload-progress unserializer).',
        caveat:
          'It is PHP_INI_PERDIR: do NOT rely on a .user.ini or an application ini_set() for this. On ' +
          'PHP-FPM also set it in the pool with php_admin_flag[session.upload_progress.enabled] = off ' +
          'and restart ALL worker processes. Partial mitigation: it does not replace the upgrade.',
        details: { add: 'Not set; PHP\'s default is On.', change: 'It is enabled ({value}).' },
      },
      memory_limit: {
        category: 'Mitigation recommended by PHP',
        why:
          'The trigger for CVE-2026-109618 is the abort caused by memory_limit exhaustion in the middle ' +
          'of multipart parsing. With memory_limit = -1 PHP does not abort on that limit and the ' +
          'vulnerable path is not reached that way.',
        caveat:
          'Removing the limit lets a single request consume all server memory: ALWAYS pair it with an ' +
          'external limit (cgroup memory.max, container limit or systemd MemoryMax=). Do NOT use ' +
          'RLIMIT_AS / RLIMIT_DATA (ulimit -v/-d): they trigger the same vulnerable path. On PHP-FPM set ' +
          'it with php_admin_value[memory_limit] = -1 so the application cannot restore it with ' +
          'ini_set(). Incomplete mitigation: it does not replace the upgrade.',
        details: { add: 'Not set; the default is 128M.', change: 'Current limit: {value} ({bytes}).' },
      },
      post_max_size: {
        category: 'Request size limits',
        why:
          'PHP recommends a low post_max_size as an interim measure: it reduces the amount of multipart ' +
          'data the parser processes before memory can run out. Complement it with size limits at the ' +
          'web server or proxy (client_max_body_size, LimitRequestBody), since a request without a ' +
          'usable Content-Length can bypass the initial post_max_size check.',
        caveat: 'Set it to the maximum your application really needs; 8M is PHP\'s default. It must be greater than or equal to upload_max_filesize.',
        details: { add: 'Not set (default 8M). It should be set explicitly.', change: 'Current value {value} ({bytes}) exceeds the recommended maximum of 8M.' },
      },
      upload_max_filesize: {
        category: 'Request size limits',
        why:
          'Limits the size of each uploaded file and thus the RFC 1867 parser\'s work per request. It is ' +
          'part of the request size limits PHP advises while the upgrade is not possible.',
        caveat: 'Set it to the application\'s real need; 2M is PHP\'s default.',
        details: { add: 'Not set (default 2M). It should be set explicitly.', change: 'Current value {value} ({bytes}) exceeds the recommended maximum of 2M.' },
      },
      max_file_uploads: {
        category: 'Request size limits',
        why:
          'Published proofs of concept use multipart requests with a large number of file fields (even ' +
          'empty ones) to force memory exhaustion without exceeding size limits. Capping the number of ' +
          'files per request reduces that vector.',
        caveat: 'Lower it as far as the application allows (e.g. 5 if only one file is uploaded at a time).',
        details: { add: 'Not set (default 20). It should be set explicitly and lowered if possible.', change: 'Current value {value} exceeds the recommended maximum of 20.' },
      },
      max_input_vars: {
        category: 'Request size limits',
        why:
          'Limits the number of input variables (multipart form fields) PHP accepts before aborting the ' +
          'request, reducing the parser\'s work per request.',
        caveat: 'General hardening measure, not explicitly cited in the official advisory. 1000 is PHP\'s default; some CMSs require higher values.',
        details: { info: 'Not set (default 1000). Added commented out as a reference.', change: 'Current value {value} exceeds the default of 1000.' },
      },
      fatal_error_backtraces: {
        category: 'Mitigation recommended by PHP (PHP 8.5 only)',
        why:
          'In PHP 8.5 the backtrace generated on a fatal error is one of the confirmed paths for ' +
          'CVE-2026-109619 (backtrace use-after-free + OPcache type confusion). Disabling it closes that specific path.',
        caveat:
          'The directive only exists in PHP 8.5; earlier versions ignore it (and warn at startup if set ' +
          'via php_admin_value). It only blocks the backtrace path, not other variants.',
        details: {
          skip: 'Only applies to PHP 8.5.',
          add: 'Not set; the default in 8.5 is On.',
          info: 'Only applies if you run PHP 8.5. Added commented out as a reference.',
          change: 'It is enabled ({value}).',
        },
      },
      file_uploads: {
        category: 'Attack-surface reduction (optional)',
        why:
          'If the application does not need file uploads, disabling file_uploads removes RFC 1867 file ' +
          'processing (file fields are discarded).',
        caveat:
          'OPTIONAL: it breaks every file upload. PHP still parses the regular fields of a multipart ' +
          'form, so it does NOT remove the vulnerable path entirely. Assess whether your application can ' +
          'do without uploads during the upgrade window.',
        details: {
          infoAbsent: 'Not set (default On). Added commented out for you to decide.',
          infoOn: 'Uploads are enabled. A commented-out suggestion is added for you to decide.',
        },
      },
      expose_php: {
        category: 'General hardening',
        why:
          'Hides the X-Powered-By header with the exact PHP version. Mass PHP2Shell scanners use it to ' +
          'locate vulnerable installations.',
        caveat: 'It does not mitigate the vulnerability; it only makes version fingerprinting harder.',
        details: { add: 'Not set (default On).', change: 'It is enabled ({value}).' },
      },
    },
  };
});
