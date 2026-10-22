/* Deutsche Texte für die Analyse und die Oberfläche. */
(function (root, factory) {
  const data = factory();
  if (typeof module === 'object' && module.exports) module.exports = data;
  else root.PhpIniAnalyzer.registerLocale('de', data);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return {
    code: 'de',
    severity: { critica: 'KRITISCH', alta: 'HOCH', media: 'MITTEL', baja: 'NIEDRIG' },
    status: { ok: 'OK', change: 'Ändern', add: 'Hinzufügen', info: 'Prüfen', skip: 'N/A' },
    bytes: { unlimited: 'unbegrenzt (-1)', unknown: 'unbekannt' },
    ui: {
      noFile: 'Keine Datei ausgewählt',
      sampleLoaded: 'Beispiel geladen (php.ini-production)',
      emptyAlert: 'Laden oder fügen Sie zuerst den Inhalt einer php.ini ein.',
      copied: 'Kopiert ✓',
      copy: 'In die Zwischenablage kopieren',
      clipboardError: 'Kein Zugriff auf die Zwischenablage; kopieren Sie den Text aus der Vorschau.',
      phpVersion: 'PHP-Version:',
      notDefined: 'nicht gesetzt',
      empty: '(leer)',
      alsoConditional: 'Auch in [PATH=]/[HOST=]-Abschnitten gesetzt',
      vulnerabilities: 'Schwachstellen',
      directives: 'Geprüfte Direktiven',
      phpAdvisory: 'PHP-Hinweis:',
      caution: 'Achtung:',
      scope: 'Geltungsbereich:',
      downloadSuffix: '.php2shell-kommentiert.ini',
    },
    cves: {
      'CVE-2026-109618': {
        title: 'Speicherbeschädigung nach Erschöpfung von memory_limit während des Multipart-Parsings (RFC 1867)',
        summary:
          'Eine manipulierte multipart/form-data-Anfrage erschöpft memory_limit, während PHP die ' +
          'Anfragedaten noch initialisiert. Der Abbruch hinterlässt teilweise initialisierte Strukturen, die ' +
          'die abschließende Bereinigung als gültig behandelt (Use-after-free / nicht initialisierter Zeiger). ' +
          'Dies ermöglicht die Ausführung von Code aus der Ferne ohne Authentifizierung.',
      },
      'CVE-2026-109619': {
        title: 'Veralteter globaler Zustand wird nach einem fatalen Fehler wiederverwendet (session.upload_progress / Backtrace)',
        summary:
          'Nach einem fatalen Fehler überlebt ein Teil des globalen Zustands der Anfrage (Upload-Fortschritts-' +
          'Handler der Session, Backtrace des fatalen Fehlers) die Freigabe seines Speichers, und die nächste ' +
          'vom selben Worker-Prozess bediente Anfrage verwendet ihn wieder. Ermöglicht die Ausführung von Code ' +
          'aus der Ferne ohne Authentifizierung.',
      },
    },
    version: {
      supported: 'Aktualisieren Sie so bald wie möglich auf PHP {target} (oder neuer). Die Gegenmaßnahmen in der php.ini sind vorübergehend und nur teilweise wirksam.',
      eol:
        'PHP {version} wird nicht mehr unterstützt: Es gibt keine offiziell korrigierte Version. Es existieren ' +
        'minimale Quellcode-Patches (sie deaktivieren session.upload_progress vollständig), und viele ' +
        'Distributionen (Debian, Ubuntu, RHEL) portieren sie unter Beibehaltung der Versionsnummer zurück: ' +
        'Prüfen Sie das Changelog des Pakets, nicht php -v. Planen Sie die Migration auf PHP 8.2+ (8.2 erhält ' +
        'nur bis zum 31.12.2026 Sicherheitskorrekturen).',
      old:
        'PHP 7.3 oder älter: Es ist kein Patch verfügbar. Wenden Sie die Gegenmaßnahmen an, isolieren Sie den ' +
        'Dienst und migrieren Sie dringend auf PHP 8.2 oder neuer (8.3 oder 8.4 empfohlen).',
      unknown:
        'Korrigierte Versionen: 8.5.12, 8.4.27, 8.3.36 und 8.2.35. Für 7.4, 8.0 und 8.1 gibt es nur ' +
        'Quellcode- oder Distributions-Backports; ältere Versionen haben keine Korrektur.',
    },
    annotate: {
      header: [
        'php.ini automatisch kommentiert - PHP2Shell-Gegenmaßnahmen',
        'CVE-2026-109618 / CVE-2026-109619 (INCIBE-CERT-Warnung vom 21.10.2026, kritisch)',
      ],
      generated: 'Erzeugt am {date} - angegebene PHP-Version: {version}',
      versionNotGiven: 'nicht angegeben',
      disclaimer: [
        'Diese Gegenmaßnahmen sind VORÜBERGEHEND und NUR TEILWEISE wirksam. Die einzige vollständige',
        'Behebung ist das Aktualisieren von PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) und der Neustart',
        'von PHP-FPM / Apache. Geänderte Originalzeilen bleiben mit dem Präfix ";;OLD" auskommentiert.',
        'Prüfen Sie jede Änderung, bevor Sie sie in der Produktion anwenden.',
      ],
      reason: 'Grund:',
      caution: 'Achtung:',
      actionChange: 'VORGESCHLAGENE ÄNDERUNG',
      actionAdded: 'DIREKTIVE HINZUGEFÜGT',
      actionOptional: 'OPTIONALER VORSCHLAG (auskommentiert)',
      actionReview: 'OPTIONALE PRÜFUNG (keine Änderung)',
      suggestionIfApplicable: 'Vorschlag, falls zutreffend:',
      okInline: ';; PHP2Shell: OK, Wert bereits sicher',
      end: ';; --- Ende PHP2Shell ---',
      missingHeader: [
        'PHP2Shell: in der Originaldatei NICHT vorhandene Direktiven',
        'Am Ende angefügt: In der php.ini gilt das letzte Vorkommen einer Direktive.',
      ],
      conditionalWarning: [
        'ACHTUNG PHP2Shell: Die folgenden Direktiven werden auch in [PATH=...]- / [HOST=...]-',
        'Abschnitten neu definiert und haben für diese Hosts/Pfade Vorrang. Bitte manuell prüfen:',
      ],
      conditionalLine: '{key} in den Zeilen {lines}',
      footer: [
        'Abschließende PHP2Shell-Erinnerung: Starten Sie nach den Änderungen ALLE Prozesse neu',
        '(systemctl restart php-fpm / apache2) und prüfen Sie mit php --ini und php -i.',
      ],
    },
    rules: {
      'session.upload_progress.enabled': {
        category: 'Von PHP empfohlene Gegenmaßnahme',
        why:
          'Deaktiviert den Upload-Fortschritts-Handler der Session, dessen veralteter globaler Zustand der ' +
          'bestätigte Ausnutzungspfad für CVE-2026-109619 ist. Verringert auch die Angriffsfläche von ' +
          'CVE-2026-109618 (der Unserializer des Upload-Fortschritts).',
        caveat:
          'Sie ist PHP_INI_PERDIR: Verlassen Sie sich NICHT auf eine .user.ini oder ein ini_set() der ' +
          'Anwendung. Setzen Sie sie bei PHP-FPM zusätzlich im Pool mit ' +
          'php_admin_flag[session.upload_progress.enabled] = off und starten Sie ALLE Worker-Prozesse neu. ' +
          'Teilweise Gegenmaßnahme: ersetzt das Update nicht.',
        details: { add: 'Nicht gesetzt; der Standardwert von PHP ist On.', change: 'Sie ist aktiviert ({value}).' },
      },
      memory_limit: {
        category: 'Von PHP empfohlene Gegenmaßnahme',
        why:
          'Der Auslöser von CVE-2026-109618 ist der Abbruch durch Erschöpfung von memory_limit mitten im ' +
          'Multipart-Parsing. Mit memory_limit = -1 bricht PHP wegen dieser Grenze nicht ab, und der ' +
          'verwundbare Pfad wird auf diesem Weg nicht erreicht.',
        caveat:
          'Ohne Grenze kann eine einzige Anfrage den gesamten Serverspeicher belegen: Kombinieren Sie sie ' +
          'IMMER mit einer externen Grenze (cgroup memory.max, Container-Limit oder MemoryMax= von systemd). ' +
          'Verwenden Sie NICHT RLIMIT_AS / RLIMIT_DATA (ulimit -v/-d): Sie lösen denselben verwundbaren Pfad ' +
          'aus. Setzen Sie sie bei PHP-FPM mit php_admin_value[memory_limit] = -1, damit die Anwendung sie ' +
          'nicht per ini_set() zurücksetzen kann. Unvollständige Gegenmaßnahme: ersetzt das Update nicht.',
        details: { add: 'Nicht gesetzt; der Standardwert ist 128M.', change: 'Aktuelle Grenze: {value} ({bytes}).' },
      },
      post_max_size: {
        category: 'Größenbeschränkungen für Anfragen',
        why:
          'PHP empfiehlt als Übergangsmaßnahme ein niedriges post_max_size: Es reduziert die Menge an ' +
          'Multipart-Daten, die der Parser verarbeitet, bevor der Speicher knapp werden kann. Ergänzen Sie es ' +
          'durch Größenbeschränkungen am Webserver oder Proxy (client_max_body_size, LimitRequestBody), da ' +
          'eine Anfrage ohne verwertbares Content-Length die anfängliche post_max_size-Prüfung umgehen kann.',
        caveat: 'Setzen Sie den Wert auf das tatsächlich benötigte Maximum Ihrer Anwendung; 8M ist der Standardwert von PHP. Er muss größer oder gleich upload_max_filesize sein.',
        details: { add: 'Nicht gesetzt (Standard 8M). Sollte explizit gesetzt werden.', change: 'Der aktuelle Wert {value} ({bytes}) überschreitet das empfohlene Maximum von 8M.' },
      },
      upload_max_filesize: {
        category: 'Größenbeschränkungen für Anfragen',
        why:
          'Begrenzt die Größe jeder hochgeladenen Datei und damit die Arbeit des RFC-1867-Parsers pro Anfrage. ' +
          'Gehört zu den Größenbeschränkungen, die PHP empfiehlt, solange kein Update möglich ist.',
        caveat: 'Setzen Sie den Wert auf den tatsächlichen Bedarf der Anwendung; 2M ist der Standardwert von PHP.',
        details: { add: 'Nicht gesetzt (Standard 2M). Sollte explizit gesetzt werden.', change: 'Der aktuelle Wert {value} ({bytes}) überschreitet das empfohlene Maximum von 2M.' },
      },
      max_file_uploads: {
        category: 'Größenbeschränkungen für Anfragen',
        why:
          'Veröffentlichte Proof-of-Concepts verwenden Multipart-Anfragen mit sehr vielen Dateifeldern (auch ' +
          'leeren), um die Speichererschöpfung zu erzwingen, ohne die Größenlimits zu überschreiten. Eine ' +
          'Obergrenze für Dateien pro Anfrage verringert diesen Vektor.',
        caveat: 'Senken Sie den Wert so weit, wie es die Anwendung erlaubt (z. B. 5, wenn jeweils nur eine Datei hochgeladen wird).',
        details: { add: 'Nicht gesetzt (Standard 20). Sollte explizit gesetzt und nach Möglichkeit gesenkt werden.', change: 'Der aktuelle Wert {value} überschreitet das empfohlene Maximum von 20.' },
      },
      max_input_vars: {
        category: 'Größenbeschränkungen für Anfragen',
        why:
          'Begrenzt die Anzahl der Eingabevariablen (Felder des Multipart-Formulars), die PHP akzeptiert, ' +
          'bevor es die Anfrage abbricht, und reduziert so die Arbeit des Parsers pro Anfrage.',
        caveat: 'Allgemeine Härtungsmaßnahme, in der offiziellen Warnung nicht ausdrücklich genannt. 1000 ist der Standardwert von PHP; manche CMS benötigen höhere Werte.',
        details: { info: 'Nicht gesetzt (Standard 1000). Als Referenz auskommentiert hinzugefügt.', change: 'Der aktuelle Wert {value} überschreitet den Standardwert von 1000.' },
      },
      fatal_error_backtraces: {
        category: 'Von PHP empfohlene Gegenmaßnahme (nur PHP 8.5)',
        why:
          'In PHP 8.5 ist der bei einem fatalen Fehler erzeugte Backtrace einer der bestätigten Pfade für ' +
          'CVE-2026-109619 (Use-after-free des Backtrace + Typverwechslung in OPcache). Das Deaktivieren ' +
          'schließt genau diesen Pfad.',
        caveat:
          'Die Direktive existiert nur in PHP 8.5; ältere Versionen ignorieren sie (und warnen beim Start, wenn ' +
          'sie per php_admin_value gesetzt ist). Sie blockiert nur den Backtrace-Pfad, keine anderen Varianten.',
        details: {
          skip: 'Gilt nur für PHP 8.5.',
          add: 'Nicht gesetzt; der Standardwert in 8.5 ist On.',
          info: 'Gilt nur, wenn Sie PHP 8.5 verwenden. Als Referenz auskommentiert hinzugefügt.',
          change: 'Sie ist aktiviert ({value}).',
        },
      },
      file_uploads: {
        category: 'Verringerung der Angriffsfläche (optional)',
        why:
          'Wenn die Anwendung keine Datei-Uploads benötigt, entfernt das Deaktivieren von file_uploads die ' +
          'RFC-1867-Dateiverarbeitung (Dateifelder werden verworfen).',
        caveat:
          'OPTIONAL: unterbindet jeden Datei-Upload. PHP parst weiterhin die normalen Felder eines ' +
          'Multipart-Formulars, der verwundbare Pfad wird also NICHT vollständig beseitigt. Prüfen Sie, ob Ihre ' +
          'Anwendung während des Update-Zeitfensters ohne Uploads auskommt.',
        details: {
          infoAbsent: 'Nicht gesetzt (Standard On). Auskommentiert hinzugefügt, damit Sie entscheiden können.',
          infoOn: 'Uploads sind aktiviert. Ein auskommentierter Vorschlag wird hinzugefügt, damit Sie entscheiden können.',
        },
      },
      expose_php: {
        category: 'Allgemeine Härtung',
        why:
          'Verbirgt den X-Powered-By-Header mit der genauen PHP-Version. Massen-Scanner für PHP2Shell nutzen ' +
          'ihn, um verwundbare Installationen zu finden.',
        caveat: 'Behebt die Schwachstelle nicht; erschwert lediglich das Erkennen der Version.',
        details: { add: 'Nicht gesetzt (Standard On).', change: 'Sie ist aktiviert ({value}).' },
      },
    },
  };
});
