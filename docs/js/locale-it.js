/* Testi in italiano per l'analizzatore e l'interfaccia. */
(function (root, factory) {
  const data = factory();
  if (typeof module === 'object' && module.exports) module.exports = data;
  else root.PhpIniAnalyzer.registerLocale('it', data);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return {
    code: 'it',
    severity: { critica: 'CRITICA', alta: 'ALTA', media: 'MEDIA', baja: 'BASSA' },
    status: { ok: 'OK', change: 'Modifica', add: 'Aggiungi', info: 'Verifica', skip: 'N/D' },
    bytes: { unlimited: 'illimitato (-1)', unknown: 'sconosciuto' },
    ui: {
      noFile: 'Nessun file selezionato',
      sampleLoaded: 'Esempio caricato (php.ini-production)',
      emptyAlert: 'Carica o incolla prima il contenuto di un php.ini.',
      copied: 'Copiato ✓',
      copy: 'Copia negli appunti',
      clipboardError: "Impossibile accedere agli appunti; copia il testo dall'anteprima.",
      phpVersion: 'Versione di PHP:',
      notDefined: 'non definita',
      empty: '(vuoto)',
      alsoConditional: 'Definita anche in sezioni [PATH=]/[HOST=]',
      vulnerabilities: 'Vulnerabilità',
      directives: 'Direttive analizzate',
      phpAdvisory: 'Avviso PHP:',
      caution: 'Attenzione:',
      scope: 'Ambito:',
      downloadSuffix: '.php2shell-annotato.ini',
    },
    cves: {
      'CVE-2026-109618': {
        title: "Corruzione della memoria dopo l'esaurimento di memory_limit durante l'analisi multipart (RFC 1867)",
        summary:
          'Una richiesta multipart/form-data manipolata esaurisce memory_limit mentre PHP sta ancora ' +
          "inizializzando i dati della richiesta. L'interruzione lascia strutture parzialmente inizializzate " +
          'che la pulizia finale considera valide (use-after-free / puntatore non inizializzato), permettendo ' +
          "l'esecuzione remota di codice senza autenticazione.",
      },
      'CVE-2026-109619': {
        title: 'Stato globale obsoleto riutilizzato dopo un errore fatale (session.upload_progress / backtrace)',
        summary:
          "Dopo un errore fatale, parte dello stato globale della richiesta (gestore dell'avanzamento di " +
          "caricamento della sessione, backtrace dell'errore fatale) sopravvive alla liberazione della sua " +
          'memoria e la richiesta successiva servita dallo stesso processo worker la riutilizza. Permette ' +
          "l'esecuzione remota di codice senza autenticazione.",
      },
    },
    version: {
      supported: 'Aggiorna a PHP {target} (o successiva) il prima possibile. Le mitigazioni di php.ini sono temporanee e parziali.',
      eol:
        'PHP {version} è fuori supporto: non esiste una versione corretta ufficiale. Esistono patch minime ' +
        'nel codice sorgente (disattivano completamente session.upload_progress) e molte distribuzioni ' +
        '(Debian, Ubuntu, RHEL) le integrano nei pacchetti mantenendo il numero di versione: controlla il ' +
        'changelog del pacchetto, non php -v. Pianifica la migrazione a PHP 8.2+ (la 8.2 riceve solo ' +
        'correzioni di sicurezza fino al 31/12/2026).',
      old:
        'PHP 7.3 o precedente: nessuna patch disponibile. Applica le mitigazioni, isola il servizio e migra ' +
        'con urgenza a PHP 8.2 o successiva (consigliate 8.3 o 8.4).',
      unknown:
        'Versioni corrette: 8.5.12, 8.4.27, 8.3.36 e 8.2.35. Per 7.4, 8.0 e 8.1 esistono solo backport nel ' +
        'sorgente o della distribuzione; le versioni precedenti non hanno correzione.',
    },
    annotate: {
      header: [
        'php.ini annotato automaticamente - mitigazioni PHP2Shell',
        'CVE-2026-109618 / CVE-2026-109619 (avviso INCIBE-CERT del 21/10/2026, critico)',
      ],
      generated: 'Generato il {date} - versione di PHP indicata: {version}',
      versionNotGiven: 'non indicata',
      disclaimer: [
        "Queste mitigazioni sono TEMPORANEE e PARZIALI. L'unica correzione completa è",
        'aggiornare PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) e riavviare PHP-FPM / Apache.',
        'Le righe originali modificate sono conservate come commento con il prefisso ";;OLD".',
        'Verifica ogni modifica prima di applicarla in produzione.',
      ],
      reason: 'Motivo:',
      caution: 'Attenzione:',
      actionChange: 'MODIFICA SUGGERITA',
      actionAdded: 'DIRETTIVA AGGIUNTA',
      actionOptional: 'SUGGERIMENTO FACOLTATIVO (commentato)',
      actionReview: 'VERIFICA FACOLTATIVA (nessuna modifica)',
      suggestionIfApplicable: 'Suggerimento se applicabile:',
      okInline: ';; PHP2Shell: OK, valore già sicuro',
      end: ';; --- fine PHP2Shell ---',
      missingHeader: [
        'PHP2Shell: direttive NON presenti nel file originale',
        "Aggiunte alla fine: in php.ini prevale l'ultima occorrenza di una direttiva.",
      ],
      conditionalWarning: [
        'ATTENZIONE PHP2Shell: le seguenti direttive sono ridefinite anche in sezioni',
        '[PATH=...] / [HOST=...] e prevalgono per quegli host/percorsi. Verificale manualmente:',
      ],
      conditionalLine: '{key} alle righe {lines}',
      footer: [
        'Promemoria finale PHP2Shell: dopo aver applicato le modifiche riavvia TUTTI i processi',
        '(systemctl restart php-fpm / apache2) e verifica con php --ini e php -i.',
      ],
    },
    rules: {
      'session.upload_progress.enabled': {
        category: 'Mitigazione raccomandata da PHP',
        why:
          "Disattiva il gestore dell'avanzamento di caricamento della sessione, il cui stato globale " +
          'obsoleto è la via di sfruttamento confermata di CVE-2026-109619. Riduce anche la superficie di ' +
          "CVE-2026-109618 (il deserializzatore dell'avanzamento di caricamento).",
        caveat:
          "È PHP_INI_PERDIR: NON affidarti a un .user.ini né a un ini_set() dell'applicazione. Con PHP-FPM " +
          'impostala anche nel pool con php_admin_flag[session.upload_progress.enabled] = off e riavvia ' +
          "TUTTI i processi worker. Mitigazione parziale: non sostituisce l'aggiornamento.",
        details: { add: 'Non definita; il valore predefinito di PHP è On.', change: 'È attiva ({value}).' },
      },
      memory_limit: {
        category: 'Mitigazione raccomandata da PHP',
        why:
          "L'innesco di CVE-2026-109618 è l'interruzione per esaurimento di memory_limit nel mezzo " +
          "dell'analisi multipart. Con memory_limit = -1 PHP non si interrompe per quel limite e il percorso " +
          'vulnerabile non viene raggiunto per quella via.',
        caveat:
          "Senza limite, una sola richiesta può consumare tutta la memoria del server: affiancala SEMPRE a un " +
          'limite esterno (cgroup memory.max, limite del container o MemoryMax= di systemd). NON usare ' +
          'RLIMIT_AS / RLIMIT_DATA (ulimit -v/-d): innescano lo stesso percorso vulnerabile. Con PHP-FPM ' +
          "impostala con php_admin_value[memory_limit] = -1 così l'applicazione non può ripristinarla con " +
          "ini_set(). Mitigazione incompleta: non sostituisce l'aggiornamento.",
        details: { add: 'Non definita; il valore predefinito è 128M.', change: 'Limite attuale: {value} ({bytes}).' },
      },
      post_max_size: {
        category: 'Limiti di dimensione delle richieste',
        why:
          'PHP raccomanda un post_max_size basso come misura provvisoria: riduce la quantità di dati ' +
          "multipart che l'analizzatore elabora prima che la memoria possa esaurirsi. Va integrato con limiti " +
          'di dimensione sul server web o sul proxy (client_max_body_size, LimitRequestBody), perché una ' +
          'richiesta senza Content-Length utilizzabile può aggirare il controllo iniziale di post_max_size.',
        caveat: 'Imposta il valore al massimo realmente necessario alla tua applicazione; 8M è il valore predefinito di PHP. Deve essere maggiore o uguale a upload_max_filesize.',
        details: { add: 'Non definita (predefinito 8M). Conviene impostarla esplicitamente.', change: 'Il valore attuale {value} ({bytes}) supera il massimo raccomandato di 8M.' },
      },
      upload_max_filesize: {
        category: 'Limiti di dimensione delle richieste',
        why:
          "Limita la dimensione di ogni file caricato e quindi il lavoro dell'analizzatore RFC 1867 per " +
          "richiesta. Fa parte dei limiti di dimensione che PHP consiglia finché non è possibile aggiornare.",
        caveat: "Imposta il valore in base alla reale necessità dell'applicazione; 2M è il valore predefinito di PHP.",
        details: { add: 'Non definita (predefinito 2M). Conviene impostarla esplicitamente.', change: 'Il valore attuale {value} ({bytes}) supera il massimo raccomandato di 2M.' },
      },
      max_file_uploads: {
        category: 'Limiti di dimensione delle richieste',
        why:
          'Le proof of concept pubblicate usano richieste multipart con un gran numero di campi file (anche ' +
          "vuoti) per forzare l'esaurimento della memoria senza superare i limiti di dimensione. Limitare il " +
          'numero di file per richiesta riduce questo vettore.',
        caveat: "Abbassa il valore quanto l'applicazione consente (ad es. 5 se si carica un solo file alla volta).",
        details: { add: 'Non definita (predefinito 20). Conviene impostarla esplicitamente e abbassarla se possibile.', change: 'Il valore attuale {value} supera il massimo raccomandato di 20.' },
      },
      max_input_vars: {
        category: 'Limiti di dimensione delle richieste',
        why:
          'Limita il numero di variabili di input (campi del modulo multipart) che PHP accetta prima di ' +
          "interrompere la richiesta, riducendo il lavoro dell'analizzatore per richiesta.",
        caveat: "Misura di irrobustimento generale, non citata espressamente nell'avviso ufficiale. 1000 è il valore predefinito di PHP; alcuni CMS richiedono valori più alti.",
        details: { info: 'Non definita (predefinito 1000). Aggiunta commentata come riferimento.', change: 'Il valore attuale {value} supera il valore predefinito di 1000.' },
      },
      fatal_error_backtraces: {
        category: 'Mitigazione raccomandata da PHP (solo PHP 8.5)',
        why:
          'In PHP 8.5 il backtrace generato in un errore fatale è una delle vie confermate di ' +
          'CVE-2026-109619 (use-after-free del backtrace + confusione di tipi in OPcache). Disattivarlo chiude ' +
          'quella via specifica.',
        caveat:
          "La direttiva esiste solo in PHP 8.5; le versioni precedenti la ignorano (ed emettono un avviso " +
          "all'avvio se impostata con php_admin_value). Blocca solo la via del backtrace, non altre varianti.",
        details: {
          skip: 'Si applica solo a PHP 8.5.',
          add: 'Non definita; il valore predefinito in 8.5 è On.',
          info: 'Si applica solo se usi PHP 8.5. Aggiunta commentata come riferimento.',
          change: 'È attiva ({value}).',
        },
      },
      file_uploads: {
        category: 'Riduzione della superficie (facoltativo)',
        why:
          "Se l'applicazione non ha bisogno di caricare file, disattivare file_uploads elimina " +
          "l'elaborazione dei file RFC 1867 (i campi file vengono scartati).",
        caveat:
          'FACOLTATIVO: interrompe qualsiasi caricamento di file. PHP continua ad analizzare i campi normali ' +
          'di un modulo multipart, quindi NON elimina del tutto il percorso vulnerabile. Valuta se la tua ' +
          "applicazione può fare a meno dei caricamenti durante la finestra di aggiornamento.",
        details: {
          infoAbsent: 'Non definita (predefinito On). Aggiunta commentata perché tu decida.',
          infoOn: 'I caricamenti sono attivi. Viene aggiunto un suggerimento commentato perché tu decida.',
        },
      },
      expose_php: {
        category: 'Irrobustimento generale',
        why:
          "Nasconde l'intestazione X-Powered-By con la versione esatta di PHP. Gli scanner massivi di " +
          'PHP2Shell la usano per individuare installazioni vulnerabili.',
        caveat: "Non mitiga la vulnerabilità; rende solo più difficile l'identificazione della versione.",
        details: { add: 'Non definita (predefinito On).', change: 'È attiva ({value}).' },
      },
    },
  };
});
