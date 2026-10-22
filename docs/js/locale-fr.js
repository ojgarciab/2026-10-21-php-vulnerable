/* Textes en français pour l'analyseur et l'interface. */
(function (root, factory) {
  const data = factory();
  if (typeof module === 'object' && module.exports) module.exports = data;
  else root.PhpIniAnalyzer.registerLocale('fr', data);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return {
    code: 'fr',
    severity: { critica: 'CRITIQUE', alta: 'ÉLEVÉE', media: 'MOYENNE', baja: 'FAIBLE' },
    status: { ok: 'OK', change: 'Modifier', add: 'Ajouter', info: 'Vérifier', skip: 'N/A' },
    bytes: { unlimited: 'illimité (-1)', unknown: 'inconnu' },
    ui: {
      noFile: 'Aucun fichier sélectionné',
      sampleLoaded: 'Exemple chargé (php.ini-production)',
      emptyAlert: "Chargez ou collez d'abord le contenu d'un php.ini.",
      copied: 'Copié ✓',
      copy: 'Copier dans le presse-papiers',
      clipboardError: "Accès au presse-papiers impossible ; copiez le texte depuis l'aperçu.",
      phpVersion: 'Version de PHP :',
      notDefined: 'non définie',
      empty: '(vide)',
      alsoConditional: 'Également définie dans des sections [PATH=]/[HOST=]',
      vulnerabilities: 'Vulnérabilités',
      directives: 'Directives analysées',
      phpAdvisory: 'Avis PHP :',
      caution: 'Attention :',
      scope: 'Portée :',
      downloadSuffix: '.php2shell-annote.ini',
    },
    cves: {
      'CVE-2026-109618': {
        title: "Corruption de mémoire après épuisement de memory_limit pendant l'analyse multipart (RFC 1867)",
        summary:
          "Une requête multipart/form-data forgée épuise memory_limit alors que PHP initialise encore les " +
          "données de la requête. L'abandon laisse des structures partiellement initialisées que le nettoyage " +
          "final traite comme valides (use-after-free / pointeur non initialisé), ce qui permet une exécution " +
          'de code à distance sans authentification.',
      },
      'CVE-2026-109619': {
        title: 'État global périmé réutilisé après une erreur fatale (session.upload_progress / backtrace)',
        summary:
          "Après une erreur fatale, une partie de l'état global de la requête (gestionnaire de progression " +
          "d'envoi de session, backtrace de l'erreur fatale) survit à la libération de sa mémoire et la " +
          'requête suivante servie par le même processus de travail la réutilise. Permet une exécution de ' +
          'code à distance sans authentification.',
      },
    },
    version: {
      supported: 'Mettez à jour vers PHP {target} (ou ultérieur) dès que possible. Les mesures de php.ini sont temporaires et partielles.',
      eol:
        "PHP {version} n'est plus maintenu : aucune version corrigée officielle. Des correctifs source " +
        'minimaux existent (ils désactivent complètement session.upload_progress) et de nombreuses ' +
        'distributions (Debian, Ubuntu, RHEL) les rétroportent en conservant le numéro de version : vérifiez ' +
        'le changelog du paquet, pas php -v. Planifiez la migration vers PHP 8.2+ (8.2 ne reçoit des ' +
        "correctifs de sécurité que jusqu'au 31/12/2026).",
      old:
        'PHP 7.3 ou antérieur : aucun correctif disponible. Appliquez les mesures, isolez le service et ' +
        "migrez d'urgence vers PHP 8.2 ou ultérieur (8.3 ou 8.4 recommandées).",
      unknown:
        'Versions corrigées : 8.5.12, 8.4.27, 8.3.36 et 8.2.35. Pour 7.4, 8.0 et 8.1 seuls des rétroportages ' +
        "source ou de distribution existent ; les versions antérieures n'ont pas de correctif.",
    },
    annotate: {
      header: [
        'php.ini annoté automatiquement - mesures PHP2Shell',
        'CVE-2026-109618 / CVE-2026-109619 (avis INCIBE-CERT du 21/10/2026, critique)',
      ],
      generated: 'Généré le {date} - version de PHP indiquée : {version}',
      versionNotGiven: 'non indiquée',
      disclaimer: [
        'Ces mesures sont TEMPORAIRES et PARTIELLES. La seule correction complète consiste à',
        'mettre à jour PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) et à redémarrer PHP-FPM / Apache.',
        'Les lignes originales modifiées sont conservées en commentaire avec le préfixe ";;OLD".',
        'Vérifiez chaque modification avant de l\'appliquer en production.',
      ],
      reason: 'Motif :',
      caution: 'Attention :',
      actionChange: 'MODIFICATION SUGGÉRÉE',
      actionAdded: 'DIRECTIVE AJOUTÉE',
      actionOptional: 'SUGGESTION FACULTATIVE (en commentaire)',
      actionReview: 'VÉRIFICATION FACULTATIVE (sans modification)',
      suggestionIfApplicable: 'Suggestion le cas échéant :',
      okInline: ';; PHP2Shell : OK, valeur déjà sûre',
      end: ';; --- fin PHP2Shell ---',
      missingHeader: [
        'PHP2Shell : directives ABSENTES du fichier original',
        "Ajoutées à la fin : dans php.ini, la dernière occurrence d'une directive l'emporte.",
      ],
      conditionalWarning: [
        'ATTENTION PHP2Shell : les directives suivantes sont aussi redéfinies dans des sections',
        '[PATH=...] / [HOST=...] et prévalent pour ces hôtes/chemins. Vérifiez-les manuellement :',
      ],
      conditionalLine: '{key} aux lignes {lines}',
      footer: [
        'Rappel final PHP2Shell : après application des modifications, redémarrez TOUS les processus',
        '(systemctl restart php-fpm / apache2) et vérifiez avec php --ini et php -i.',
      ],
    },
    rules: {
      'session.upload_progress.enabled': {
        category: 'Mesure recommandée par PHP',
        why:
          "Désactive le gestionnaire de progression d'envoi de session, dont l'état global périmé est la " +
          "voie d'exploitation confirmée de CVE-2026-109619. Réduit aussi la surface de CVE-2026-109618 " +
          '(le désérialiseur de progression d\'envoi).',
        caveat:
          "C'est une directive PHP_INI_PERDIR : ne comptez PAS sur un .user.ini ni sur un ini_set() de " +
          "l'application. Avec PHP-FPM, fixez-la aussi dans le pool avec " +
          'php_admin_flag[session.upload_progress.enabled] = off et redémarrez TOUS les processus de ' +
          'travail. Mesure partielle : elle ne remplace pas la mise à jour.',
        details: { add: 'Non définie ; la valeur par défaut de PHP est On.', change: 'Elle est activée ({value}).' },
      },
      memory_limit: {
        category: 'Mesure recommandée par PHP',
        why:
          "Le déclencheur de CVE-2026-109618 est l'abandon provoqué par l'épuisement de memory_limit en " +
          "plein milieu de l'analyse multipart. Avec memory_limit = -1, PHP n'abandonne pas sur cette limite " +
          "et le chemin vulnérable n'est pas atteint par cette voie.",
        caveat:
          'Sans limite, une seule requête peut consommer toute la mémoire du serveur : accompagnez-la ' +
          'TOUJOURS d\'une limite externe (cgroup memory.max, limite de conteneur ou MemoryMax= de systemd). ' +
          "N'utilisez PAS RLIMIT_AS / RLIMIT_DATA (ulimit -v/-d) : ils déclenchent le même chemin " +
          "vulnérable. Avec PHP-FPM, fixez php_admin_value[memory_limit] = -1 pour que l'application ne " +
          'puisse pas la rétablir avec ini_set(). Mesure incomplète : elle ne remplace pas la mise à jour.',
        details: { add: 'Non définie ; la valeur par défaut est 128M.', change: 'Limite actuelle : {value} ({bytes}).' },
      },
      post_max_size: {
        category: 'Limites de taille des requêtes',
        why:
          'PHP recommande un post_max_size bas comme mesure provisoire : cela réduit la quantité de données ' +
          "multipart traitées par l'analyseur avant que la mémoire ne s'épuise. À compléter par des limites " +
          'de taille sur le serveur web ou le proxy (client_max_body_size, LimitRequestBody), car une requête ' +
          'sans Content-Length exploitable peut contourner la vérification initiale de post_max_size.',
        caveat: 'Ajustez la valeur au maximum réellement nécessaire à votre application ; 8M est la valeur par défaut de PHP. Elle doit être supérieure ou égale à upload_max_filesize.',
        details: { add: 'Non définie (8M par défaut). Il convient de la fixer explicitement.', change: 'La valeur actuelle {value} ({bytes}) dépasse le maximum recommandé de 8M.' },
      },
      upload_max_filesize: {
        category: 'Limites de taille des requêtes',
        why:
          "Limite la taille de chaque fichier envoyé et donc le travail de l'analyseur RFC 1867 par requête. " +
          'Fait partie des limites de taille que PHP conseille tant que la mise à jour est impossible.',
        caveat: "Ajustez la valeur au besoin réel de l'application ; 2M est la valeur par défaut de PHP.",
        details: { add: 'Non définie (2M par défaut). Il convient de la fixer explicitement.', change: 'La valeur actuelle {value} ({bytes}) dépasse le maximum recommandé de 2M.' },
      },
      max_file_uploads: {
        category: 'Limites de taille des requêtes',
        why:
          'Les preuves de concept publiées utilisent des requêtes multipart avec un grand nombre de champs ' +
          "fichier (même vides) pour forcer l'épuisement de la mémoire sans dépasser les limites de taille. " +
          'Plafonner le nombre de fichiers par requête réduit ce vecteur.',
        caveat: "Abaissez la valeur autant que l'application le permet (p. ex. 5 si un seul fichier est envoyé à la fois).",
        details: { add: 'Non définie (20 par défaut). Il convient de la fixer explicitement et de la réduire si possible.', change: 'La valeur actuelle {value} dépasse le maximum recommandé de 20.' },
      },
      max_input_vars: {
        category: 'Limites de taille des requêtes',
        why:
          "Limite le nombre de variables d'entrée (champs du formulaire multipart) que PHP accepte avant " +
          "d'abandonner la requête, réduisant le travail de l'analyseur par requête.",
        caveat: "Mesure de durcissement générale, non citée expressément dans l'avis officiel. 1000 est la valeur par défaut de PHP ; certains CMS exigent des valeurs plus élevées.",
        details: { info: 'Non définie (1000 par défaut). Ajoutée en commentaire à titre de référence.', change: 'La valeur actuelle {value} dépasse la valeur par défaut de 1000.' },
      },
      fatal_error_backtraces: {
        category: 'Mesure recommandée par PHP (PHP 8.5 uniquement)',
        why:
          "En PHP 8.5, le backtrace généré lors d'une erreur fatale est l'une des voies confirmées de " +
          'CVE-2026-109619 (use-after-free du backtrace + confusion de types dans OPcache). Le désactiver ' +
          'ferme cette voie précise.',
        caveat:
          "La directive n'existe qu'en PHP 8.5 ; les versions antérieures l'ignorent (et émettent un " +
          'avertissement au démarrage si elle est fixée via php_admin_value). Elle ne bloque que la voie du ' +
          'backtrace, pas les autres variantes.',
        details: {
          skip: "Ne s'applique qu'à PHP 8.5.",
          add: 'Non définie ; la valeur par défaut en 8.5 est On.',
          info: "Ne s'applique que si vous utilisez PHP 8.5. Ajoutée en commentaire à titre de référence.",
          change: 'Elle est activée ({value}).',
        },
      },
      file_uploads: {
        category: "Réduction de la surface d'attaque (facultatif)",
        why:
          "Si l'application n'a pas besoin d'envoyer des fichiers, désactiver file_uploads supprime le " +
          'traitement des fichiers RFC 1867 (les champs fichier sont ignorés).',
        caveat:
          'FACULTATIF : cela casse tout envoi de fichier. PHP analyse toujours les champs ordinaires d\'un ' +
          "formulaire multipart, ce qui N'élimine PAS complètement le chemin vulnérable. Évaluez si votre " +
          'application peut se passer des envois pendant la fenêtre de mise à jour.',
        details: {
          infoAbsent: 'Non définie (On par défaut). Ajoutée en commentaire pour que vous décidiez.',
          infoOn: 'Les envois sont activés. Une suggestion en commentaire est ajoutée pour que vous décidiez.',
        },
      },
      expose_php: {
        category: 'Durcissement général',
        why:
          "Masque l'en-tête X-Powered-By contenant la version exacte de PHP. Les scanners massifs de " +
          "PHP2Shell l'utilisent pour repérer les installations vulnérables.",
        caveat: "N'atténue pas la vulnérabilité ; rend seulement l'identification de la version plus difficile.",
        details: { add: 'Non définie (On par défaut).', change: 'Elle est activée ({value}).' },
      },
    },
  };
});
