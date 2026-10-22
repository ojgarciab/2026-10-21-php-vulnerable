#!/usr/bin/env python3
"""Genera docs/<idioma>/index.html para cada idioma a partir de una plantilla única.

Uso: python3 tools/build-pages.py
Los textos de la interfaz que genera JavaScript viven en docs/js/locale-<idioma>.js.
"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "docs"

LANGS = {
    "es": {
        "name": "Español",
        "title": "Analizador php.ini · PHP2Shell",
        "description": "Analiza un php.ini en tu navegador y descarga una versión anotada con las mitigaciones de CVE-2026-109618 y CVE-2026-109619 (PHP2Shell) mientras actualizas PHP.",
        "nav_label": "Idioma",
        "eyebrow": "INCIBE-CERT · aviso 21/10/2026 · importancia crítica",
        "h1": "Analizador de <code>php.ini</code> frente a PHP2Shell",
        "lead": "Sube tu <code>php.ini</code> y obtén una copia anotada con los cambios sugeridos para mitigar <strong>CVE-2026-109618</strong> y <strong>CVE-2026-109619</strong> mientras actualizas PHP. Todo se procesa en tu navegador: el fichero nunca sale de tu equipo.",
        "step1": "1. Carga el fichero",
        "drop": "<strong>Arrastra aquí tu php.ini</strong> o pulsa para seleccionarlo",
        "nofile": "Ningún fichero seleccionado",
        "sample": "Cargar ejemplo (php.ini-production)",
        "clear": "Limpiar",
        "version_label": "Versión de PHP en el servidor",
        "v_unknown": "No lo sé / no indicar",
        "v_fixed": "{v} (corregida en {fix})",
        "v_eol": "{v} (sin soporte: solo parches de distribución)",
        "v_old": "7.3 o anterior (sin parche)",
        "version_help": "Puedes obtenerla con <code>php -v</code>. Sirve para adaptar las recomendaciones (p. ej. <code>fatal_error_backtraces</code> solo existe en 8.5).",
        "paste_label": "O pega el contenido directamente",
        "placeholder": "; contenido de php.ini",
        "analyze": "Analizar",
        "step2": "2. Resultado del análisis",
        "th": ["Estado", "Directiva", "Línea", "Valor actual", "Sugerido", "CVE", "Severidad"],
        "download": "Descargar php.ini anotado",
        "copy": "Copiar al portapapeles",
        "preview": "Ver / ocultar vista previa",
        "about": "¿Qué comprueba esta herramienta?",
        "sources": "Fuentes: aviso de INCIBE-CERT, avisos de seguridad de PHP (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp), PHP Foundation, Red Hat, Cloudflare, Wiz, watchTowr, Sansec, Qualys. Consulta el <a href=\"https://github.com/ojgarciab/2026-10-21-php-vulnerable#readme\">README</a> del proyecto.",
        "footer": "Herramienta de apoyo, sin garantías. Las mitigaciones de <code>php.ini</code> son parciales: la única corrección completa es actualizar PHP y reiniciar todos los procesos.",
    },
    "en": {
        "name": "English",
        "title": "php.ini Analyzer · PHP2Shell",
        "description": "Analyze a php.ini in your browser and download an annotated version with the mitigations for CVE-2026-109618 and CVE-2026-109619 (PHP2Shell) while you upgrade PHP.",
        "nav_label": "Language",
        "eyebrow": "INCIBE-CERT · advisory 2026-10-21 · critical severity",
        "h1": "<code>php.ini</code> analyzer against PHP2Shell",
        "lead": "Upload your <code>php.ini</code> and get an annotated copy with the suggested changes to mitigate <strong>CVE-2026-109618</strong> and <strong>CVE-2026-109619</strong> while you upgrade PHP. Everything runs in your browser: the file never leaves your computer.",
        "step1": "1. Load the file",
        "drop": "<strong>Drop your php.ini here</strong> or click to choose it",
        "nofile": "No file selected",
        "sample": "Load sample (php.ini-production)",
        "clear": "Clear",
        "version_label": "PHP version on the server",
        "v_unknown": "Unknown / don't specify",
        "v_fixed": "{v} (fixed in {fix})",
        "v_eol": "{v} (end-of-life: distribution patches only)",
        "v_old": "7.3 or earlier (no patch)",
        "version_help": "You can get it with <code>php -v</code>. It tailors the recommendations (e.g. <code>fatal_error_backtraces</code> only exists in 8.5).",
        "paste_label": "Or paste the contents directly",
        "placeholder": "; php.ini contents",
        "analyze": "Analyze",
        "step2": "2. Analysis results",
        "th": ["Status", "Directive", "Line", "Current value", "Suggested", "CVE", "Severity"],
        "download": "Download annotated php.ini",
        "copy": "Copy to clipboard",
        "preview": "Show / hide preview",
        "about": "What does this tool check?",
        "sources": "Sources: INCIBE-CERT advisory, PHP security advisories (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp), PHP Foundation, Red Hat, Cloudflare, Wiz, watchTowr, Sansec, Qualys. See the project <a href=\"https://github.com/ojgarciab/2026-10-21-php-vulnerable#readme\">README</a>.",
        "footer": "Support tool, provided without warranty. <code>php.ini</code> mitigations are partial: the only complete fix is to upgrade PHP and restart every process.",
    },
    "fr": {
        "name": "Français",
        "title": "Analyseur php.ini · PHP2Shell",
        "description": "Analysez un php.ini dans votre navigateur et téléchargez une version annotée avec les mesures d'atténuation de CVE-2026-109618 et CVE-2026-109619 (PHP2Shell) pendant la mise à jour de PHP.",
        "nav_label": "Langue",
        "eyebrow": "INCIBE-CERT · avis du 21/10/2026 · gravité critique",
        "h1": "Analyseur de <code>php.ini</code> contre PHP2Shell",
        "lead": "Chargez votre <code>php.ini</code> et obtenez une copie annotée avec les modifications suggérées pour atténuer <strong>CVE-2026-109618</strong> et <strong>CVE-2026-109619</strong> pendant la mise à jour de PHP. Tout est traité dans votre navigateur : le fichier ne quitte jamais votre ordinateur.",
        "step1": "1. Chargez le fichier",
        "drop": "<strong>Déposez votre php.ini ici</strong> ou cliquez pour le sélectionner",
        "nofile": "Aucun fichier sélectionné",
        "sample": "Charger l'exemple (php.ini-production)",
        "clear": "Effacer",
        "version_label": "Version de PHP sur le serveur",
        "v_unknown": "Je ne sais pas / ne pas indiquer",
        "v_fixed": "{v} (corrigée dans {fix})",
        "v_eol": "{v} (fin de vie : correctifs de distribution uniquement)",
        "v_old": "7.3 ou antérieure (aucun correctif)",
        "version_help": "Obtenez-la avec <code>php -v</code>. Elle permet d'adapter les recommandations (par ex. <code>fatal_error_backtraces</code> n'existe qu'en 8.5).",
        "paste_label": "Ou collez directement le contenu",
        "placeholder": "; contenu de php.ini",
        "analyze": "Analyser",
        "step2": "2. Résultat de l'analyse",
        "th": ["État", "Directive", "Ligne", "Valeur actuelle", "Suggérée", "CVE", "Gravité"],
        "download": "Télécharger le php.ini annoté",
        "copy": "Copier dans le presse-papiers",
        "preview": "Afficher / masquer l'aperçu",
        "about": "Que vérifie cet outil ?",
        "sources": "Sources : avis INCIBE-CERT, avis de sécurité PHP (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp), PHP Foundation, Red Hat, Cloudflare, Wiz, watchTowr, Sansec, Qualys. Consultez le <a href=\"https://github.com/ojgarciab/2026-10-21-php-vulnerable#readme\">README</a> du projet.",
        "footer": "Outil d'aide, fourni sans garantie. Les mesures d'atténuation de <code>php.ini</code> sont partielles : la seule correction complète est de mettre à jour PHP et de redémarrer tous les processus.",
    },
    "it": {
        "name": "Italiano",
        "title": "Analizzatore php.ini · PHP2Shell",
        "description": "Analizza un php.ini nel browser e scarica una versione annotata con le mitigazioni per CVE-2026-109618 e CVE-2026-109619 (PHP2Shell) mentre aggiorni PHP.",
        "nav_label": "Lingua",
        "eyebrow": "INCIBE-CERT · avviso del 21/10/2026 · gravità critica",
        "h1": "Analizzatore di <code>php.ini</code> contro PHP2Shell",
        "lead": "Carica il tuo <code>php.ini</code> e ottieni una copia annotata con le modifiche suggerite per mitigare <strong>CVE-2026-109618</strong> e <strong>CVE-2026-109619</strong> mentre aggiorni PHP. Tutto viene elaborato nel browser: il file non lascia mai il tuo computer.",
        "step1": "1. Carica il file",
        "drop": "<strong>Trascina qui il tuo php.ini</strong> o fai clic per selezionarlo",
        "nofile": "Nessun file selezionato",
        "sample": "Carica esempio (php.ini-production)",
        "clear": "Pulisci",
        "version_label": "Versione di PHP sul server",
        "v_unknown": "Non lo so / non indicare",
        "v_fixed": "{v} (corretta in {fix})",
        "v_eol": "{v} (fuori supporto: solo patch della distribuzione)",
        "v_old": "7.3 o precedente (nessuna patch)",
        "version_help": "Puoi ottenerla con <code>php -v</code>. Serve ad adattare le raccomandazioni (ad es. <code>fatal_error_backtraces</code> esiste solo in 8.5).",
        "paste_label": "Oppure incolla direttamente il contenuto",
        "placeholder": "; contenuto di php.ini",
        "analyze": "Analizza",
        "step2": "2. Risultato dell'analisi",
        "th": ["Stato", "Direttiva", "Riga", "Valore attuale", "Suggerito", "CVE", "Gravità"],
        "download": "Scarica php.ini annotato",
        "copy": "Copia negli appunti",
        "preview": "Mostra / nascondi anteprima",
        "about": "Cosa controlla questo strumento?",
        "sources": "Fonti: avviso INCIBE-CERT, avvisi di sicurezza PHP (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp), PHP Foundation, Red Hat, Cloudflare, Wiz, watchTowr, Sansec, Qualys. Consulta il <a href=\"https://github.com/ojgarciab/2026-10-21-php-vulnerable#readme\">README</a> del progetto.",
        "footer": "Strumento di supporto, senza garanzie. Le mitigazioni di <code>php.ini</code> sono parziali: l'unica correzione completa è aggiornare PHP e riavviare tutti i processi.",
    },
    "de": {
        "name": "Deutsch",
        "title": "php.ini-Analyse · PHP2Shell",
        "description": "Analysieren Sie eine php.ini im Browser und laden Sie eine kommentierte Version mit den Gegenmaßnahmen zu CVE-2026-109618 und CVE-2026-109619 (PHP2Shell) herunter, während Sie PHP aktualisieren.",
        "nav_label": "Sprache",
        "eyebrow": "INCIBE-CERT · Warnung vom 21.10.2026 · Schweregrad kritisch",
        "h1": "<code>php.ini</code>-Analyse gegen PHP2Shell",
        "lead": "Laden Sie Ihre <code>php.ini</code> hoch und erhalten Sie eine kommentierte Kopie mit den vorgeschlagenen Änderungen zur Abschwächung von <strong>CVE-2026-109618</strong> und <strong>CVE-2026-109619</strong>, während Sie PHP aktualisieren. Alles wird im Browser verarbeitet: Die Datei verlässt Ihren Rechner nie.",
        "step1": "1. Datei laden",
        "drop": "<strong>Ziehen Sie Ihre php.ini hierher</strong> oder klicken Sie, um sie auszuwählen",
        "nofile": "Keine Datei ausgewählt",
        "sample": "Beispiel laden (php.ini-production)",
        "clear": "Leeren",
        "version_label": "PHP-Version auf dem Server",
        "v_unknown": "Unbekannt / nicht angeben",
        "v_fixed": "{v} (behoben in {fix})",
        "v_eol": "{v} (ohne Support: nur Distributions-Patches)",
        "v_old": "7.3 oder älter (kein Patch)",
        "version_help": "Sie erhalten sie mit <code>php -v</code>. Damit werden die Empfehlungen angepasst (z. B. gibt es <code>fatal_error_backtraces</code> nur in 8.5).",
        "paste_label": "Oder Inhalt direkt einfügen",
        "placeholder": "; Inhalt der php.ini",
        "analyze": "Analysieren",
        "step2": "2. Ergebnis der Analyse",
        "th": ["Status", "Direktive", "Zeile", "Aktueller Wert", "Vorschlag", "CVE", "Schweregrad"],
        "download": "Kommentierte php.ini herunterladen",
        "copy": "In die Zwischenablage kopieren",
        "preview": "Vorschau ein-/ausblenden",
        "about": "Was prüft dieses Werkzeug?",
        "sources": "Quellen: INCIBE-CERT-Warnung, PHP-Sicherheitshinweise (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp), PHP Foundation, Red Hat, Cloudflare, Wiz, watchTowr, Sansec, Qualys. Siehe die <a href=\"https://github.com/ojgarciab/2026-10-21-php-vulnerable#readme\">README</a> des Projekts.",
        "footer": "Hilfswerkzeug ohne Gewähr. Die Gegenmaßnahmen in der <code>php.ini</code> sind nur teilweise wirksam: Die einzige vollständige Behebung ist das Aktualisieren von PHP und der Neustart aller Prozesse.",
    },
    "pt": {
        "name": "Português",
        "title": "Analisador php.ini · PHP2Shell",
        "description": "Analise um php.ini no seu navegador e descarregue uma versão anotada com as mitigações para CVE-2026-109618 e CVE-2026-109619 (PHP2Shell) enquanto atualiza o PHP.",
        "nav_label": "Idioma",
        "eyebrow": "INCIBE-CERT · aviso de 21/10/2026 · gravidade crítica",
        "h1": "Analisador de <code>php.ini</code> contra o PHP2Shell",
        "lead": "Carregue o seu <code>php.ini</code> e obtenha uma cópia anotada com as alterações sugeridas para mitigar <strong>CVE-2026-109618</strong> e <strong>CVE-2026-109619</strong> enquanto atualiza o PHP. Tudo é processado no seu navegador: o ficheiro nunca sai do seu computador.",
        "step1": "1. Carregue o ficheiro",
        "drop": "<strong>Arraste aqui o seu php.ini</strong> ou clique para o selecionar",
        "nofile": "Nenhum ficheiro selecionado",
        "sample": "Carregar exemplo (php.ini-production)",
        "clear": "Limpar",
        "version_label": "Versão do PHP no servidor",
        "v_unknown": "Não sei / não indicar",
        "v_fixed": "{v} (corrigida em {fix})",
        "v_eol": "{v} (sem suporte: apenas patches da distribuição)",
        "v_old": "7.3 ou anterior (sem patch)",
        "version_help": "Pode obtê-la com <code>php -v</code>. Serve para adaptar as recomendações (p. ex. <code>fatal_error_backtraces</code> só existe na 8.5).",
        "paste_label": "Ou cole o conteúdo diretamente",
        "placeholder": "; conteúdo do php.ini",
        "analyze": "Analisar",
        "step2": "2. Resultado da análise",
        "th": ["Estado", "Diretiva", "Linha", "Valor atual", "Sugerido", "CVE", "Gravidade"],
        "download": "Descarregar php.ini anotado",
        "copy": "Copiar para a área de transferência",
        "preview": "Mostrar / ocultar pré-visualização",
        "about": "O que verifica esta ferramenta?",
        "sources": "Fontes: aviso do INCIBE-CERT, avisos de segurança do PHP (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp), PHP Foundation, Red Hat, Cloudflare, Wiz, watchTowr, Sansec, Qualys. Consulte o <a href=\"https://github.com/ojgarciab/2026-10-21-php-vulnerable#readme\">README</a> do projeto.",
        "footer": "Ferramenta de apoio, sem garantias. As mitigações do <code>php.ini</code> são parciais: a única correção completa é atualizar o PHP e reiniciar todos os processos.",
    },
}

FIXED = [("8.5", "8.5.12"), ("8.4", "8.4.27"), ("8.3", "8.3.36"), ("8.2", "8.2.35")]
EOL = ["8.1", "8.0", "7.4"]
FAVICON = "data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 32 32%22%3E%3Crect width=%2232%22 height=%2232%22 rx=%226%22 fill=%22%234f46e5%22/%3E%3Ctext x=%2216%22 y=%2222%22 font-size=%2216%22 text-anchor=%22middle%22 fill=%22white%22 font-family=%22sans-serif%22 font-weight=%22bold%22%3Eini%3C/text%3E%3C/svg%3E"

TEMPLATE = """<!doctype html>
<!-- Generado por tools/build-pages.py: edita la plantilla y vuelve a ejecutarlo. -->
<html lang="{lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <meta name="description" content="{description}">
{hreflangs}
  <link rel="icon" href="{favicon}">
  <link rel="stylesheet" href="../css/style.css">
</head>
<body>
  <header class="hero">
    <div class="wrap">
      <nav class="lang" aria-label="{nav_label}">
        {nav}
      </nav>
      <p class="eyebrow">{eyebrow}</p>
      <h1>{h1}</h1>
      <p class="lead">{lead}</p>
    </div>
  </header>

  <main class="wrap">
    <section class="card" id="input-card">
      <h2>{step1}</h2>
      <div class="grid-2">
        <div>
          <label class="dropzone" id="dropzone" for="file-input" tabindex="0">
            <input type="file" id="file-input" accept=".ini,text/plain,*/*" hidden>
            <span class="drop-icon" aria-hidden="true">⇪</span>
            <span>{drop}</span>
            <span class="muted" id="file-name">{nofile}</span>
          </label>
          <div class="row">
            <button type="button" class="btn secondary" id="btn-sample">{sample}</button>
            <button type="button" class="btn secondary" id="btn-clear">{clear}</button>
          </div>
        </div>
        <div>
          <label for="version">{version_label}</label>
          <select id="version">
            <option value="unknown">{v_unknown}</option>
{options}
          </select>
          <p class="help">{version_help}</p>
          <label for="ini-text">{paste_label}</label>
          <textarea id="ini-text" rows="10" spellcheck="false" placeholder="{placeholder}"></textarea>
          <div class="row">
            <button type="button" class="btn primary" id="btn-analyze">{analyze}</button>
          </div>
        </div>
      </div>
    </section>

    <section class="card hidden" id="result-card">
      <h2>{step2}</h2>
      <div id="version-banner" class="banner"></div>
      <div class="summary" id="summary"></div>
      <table class="findings" id="findings">
        <thead>
          <tr>
{ths}
          </tr>
        </thead>
        <tbody></tbody>
      </table>
      <div class="row">
        <button type="button" class="btn primary" id="btn-download">{download}</button>
        <button type="button" class="btn secondary" id="btn-copy">{copy}</button>
        <button type="button" class="btn secondary" id="btn-toggle-preview">{preview}</button>
      </div>
      <pre class="preview hidden" id="preview"></pre>
    </section>

    <section class="card" id="about-card">
      <h2>{about}</h2>
      <div id="rules-doc"></div>
      <p class="muted">{sources}</p>
    </section>
  </main>

  <footer class="wrap muted">{footer}</footer>

  <script src="../js/analyzer.js"></script>
  <script src="../js/locale-{lang}.js"></script>
  <script src="../js/sample.js"></script>
  <script src="../js/app.js"></script>
</body>
</html>
"""


def build(lang, t):
    hreflangs = "\n".join(f'  <link rel="alternate" hreflang="{c}" href="../{c}/">' for c in LANGS)
    nav = " · ".join(
        f'<span aria-current="page">{LANGS[c]["name"]}</span>' if c == lang
        else f'<a href="../{c}/" hreflang="{c}" lang="{c}">{LANGS[c]["name"]}</a>'
        for c in LANGS
    )
    options = [f'            <option value="{v}">{t["v_fixed"].format(v=v, fix=fix)}</option>' for v, fix in FIXED]
    options += [f'            <option value="{v}">{t["v_eol"].format(v=v)}</option>' for v in EOL]
    options += [f'            <option value="old">{t["v_old"]}</option>']
    ths = "\n".join(f"            <th>{h}</th>" for h in t["th"])
    html = TEMPLATE.format(lang=lang, hreflangs=hreflangs, nav=nav, options="\n".join(options), ths=ths, favicon=FAVICON, **t)
    out = ROOT / lang / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print("escrito", out.relative_to(ROOT.parent))


if __name__ == "__main__":
    for lang, t in LANGS.items():
        build(lang, t)
