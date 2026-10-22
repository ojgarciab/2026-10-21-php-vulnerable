/* Textos em português para o analisador e a interface. */
(function (root, factory) {
  const data = factory();
  if (typeof module === 'object' && module.exports) module.exports = data;
  else root.PhpIniAnalyzer.registerLocale('pt', data);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return {
    code: 'pt',
    severity: { critica: 'CRÍTICA', alta: 'ALTA', media: 'MÉDIA', baja: 'BAIXA' },
    status: { ok: 'OK', change: 'Alterar', add: 'Adicionar', info: 'Rever', skip: 'N/A' },
    bytes: { unlimited: 'sem limite (-1)', unknown: 'desconhecido' },
    ui: {
      noFile: 'Nenhum ficheiro selecionado',
      sampleLoaded: 'Exemplo carregado (php.ini-production)',
      emptyAlert: 'Carregue ou cole primeiro o conteúdo de um php.ini.',
      copied: 'Copiado ✓',
      copy: 'Copiar para a área de transferência',
      clipboardError: 'Não foi possível aceder à área de transferência; copie o texto da pré-visualização.',
      phpVersion: 'Versão do PHP:',
      notDefined: 'não definida',
      empty: '(vazio)',
      alsoConditional: 'Também definida em secções [PATH=]/[HOST=]',
      vulnerabilities: 'Vulnerabilidades',
      directives: 'Diretivas analisadas',
      phpAdvisory: 'Aviso do PHP:',
      caution: 'Atenção:',
      scope: 'Âmbito:',
      downloadSuffix: '.php2shell-anotado.ini',
    },
    cves: {
      'CVE-2026-109618': {
        title: 'Corrupção de memória após esgotar memory_limit durante a análise multipart (RFC 1867)',
        summary:
          'Um pedido multipart/form-data manipulado esgota memory_limit enquanto o PHP ainda está a ' +
          'inicializar os dados do pedido. A interrupção deixa estruturas parcialmente inicializadas que a ' +
          'limpeza final trata como válidas (use-after-free / ponteiro não inicializado), o que permite a ' +
          'execução remota de código sem autenticação.',
      },
      'CVE-2026-109619': {
        title: 'Estado global obsoleto reutilizado após um erro fatal (session.upload_progress / backtrace)',
        summary:
          'Após um erro fatal, parte do estado global do pedido (gestor de progresso de carregamento da ' +
          'sessão, backtrace do erro fatal) sobrevive à libertação da sua memória e o pedido seguinte ' +
          'atendido pelo mesmo processo trabalhador reutiliza-o. Permite a execução remota de código sem ' +
          'autenticação.',
      },
    },
    version: {
      supported: 'Atualize para o PHP {target} (ou superior) o mais depressa possível. As mitigações do php.ini são temporárias e parciais.',
      eol:
        'O PHP {version} está sem suporte: não há versão oficial corrigida. Existem patches mínimos no ' +
        'código-fonte (desativam completamente session.upload_progress) e muitas distribuições (Debian, ' +
        'Ubuntu, RHEL) incorporam-nos nos pacotes mantendo o número de versão: verifique o changelog do ' +
        'pacote, não o php -v. Planeie a migração para PHP 8.2+ (a 8.2 só recebe correções de segurança ' +
        'até 31/12/2026).',
      old:
        'PHP 7.3 ou anterior: sem qualquer patch disponível. Aplique as mitigações, isole o serviço e migre ' +
        'urgentemente para PHP 8.2 ou superior (recomendadas 8.3 ou 8.4).',
      unknown:
        'Versões corrigidas: 8.5.12, 8.4.27, 8.3.36 e 8.2.35. Para 7.4, 8.0 e 8.1 só existem backports no ' +
        'código-fonte ou da distribuição; as versões anteriores não têm correção.',
    },
    annotate: {
      header: [
        'php.ini anotado automaticamente - mitigações PHP2Shell',
        'CVE-2026-109618 / CVE-2026-109619 (aviso INCIBE-CERT de 21/10/2026, crítico)',
      ],
      generated: 'Gerado em {date} - versão do PHP indicada: {version}',
      versionNotGiven: 'não indicada',
      disclaimer: [
        'Estas mitigações são TEMPORÁRIAS e PARCIAIS. A única correção completa é',
        'atualizar o PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) e reiniciar o PHP-FPM / Apache.',
        'As linhas originais alteradas ficam comentadas com o prefixo ";;OLD".',
        'Reveja cada alteração antes de a aplicar em produção.',
      ],
      reason: 'Motivo:',
      caution: 'Atenção:',
      actionChange: 'ALTERAÇÃO SUGERIDA',
      actionAdded: 'DIRETIVA ADICIONADA',
      actionOptional: 'SUGESTÃO OPCIONAL (comentada)',
      actionReview: 'REVISÃO OPCIONAL (sem alterações)',
      suggestionIfApplicable: 'Sugestão, se aplicável:',
      okInline: ';; PHP2Shell: OK, valor já seguro',
      end: ';; --- fim PHP2Shell ---',
      missingHeader: [
        'PHP2Shell: diretivas NÃO presentes no ficheiro original',
        'Adicionadas no fim: no php.ini prevalece a última ocorrência de uma diretiva.',
      ],
      conditionalWarning: [
        'ATENÇÃO PHP2Shell: as diretivas seguintes também são redefinidas dentro de secções',
        '[PATH=...] / [HOST=...] e prevalecem para esses hosts/caminhos. Reveja-as manualmente:',
      ],
      conditionalLine: '{key} nas linhas {lines}',
      footer: [
        'Lembrete final PHP2Shell: depois de aplicar as alterações reinicie TODOS os processos',
        '(systemctl restart php-fpm / apache2) e verifique com php --ini e php -i.',
      ],
    },
    rules: {
      'session.upload_progress.enabled': {
        category: 'Mitigação recomendada pelo PHP',
        why:
          'Desativa o gestor de progresso de carregamento da sessão, cujo estado global obsoleto é a via ' +
          'confirmada de exploração da CVE-2026-109619. Também reduz a superfície da CVE-2026-109618 ' +
          '(o desserializador do progresso de carregamento).',
        caveat:
          'É PHP_INI_PERDIR: NÃO confie num .user.ini nem num ini_set() da aplicação. No PHP-FPM defina-a ' +
          'também no pool com php_admin_flag[session.upload_progress.enabled] = off e reinicie TODOS os ' +
          'processos trabalhadores. Mitigação parcial: não substitui a atualização.',
        details: { add: 'Não está definida; o valor predefinido do PHP é On.', change: 'Está ativada ({value}).' },
      },
      memory_limit: {
        category: 'Mitigação recomendada pelo PHP',
        why:
          'O gatilho da CVE-2026-109618 é a interrupção por esgotamento de memory_limit a meio da análise ' +
          'multipart. Com memory_limit = -1 o PHP não interrompe por esse limite e o caminho vulnerável não ' +
          'é atingido por essa via.',
        caveat:
          'Ao retirar o limite, um único pedido pode consumir toda a memória do servidor: acompanhe-o ' +
          'SEMPRE de um limite externo (cgroup memory.max, limite do contentor ou MemoryMax= do systemd). ' +
          'NÃO use RLIMIT_AS / RLIMIT_DATA (ulimit -v/-d): provocam o mesmo caminho vulnerável. No PHP-FPM ' +
          'defina-o com php_admin_value[memory_limit] = -1 para que a aplicação não o possa repor com ' +
          'ini_set(). Mitigação incompleta: não substitui a atualização.',
        details: { add: 'Não está definida; o valor predefinido é 128M.', change: 'Limite atual: {value} ({bytes}).' },
      },
      post_max_size: {
        category: 'Limites de tamanho do pedido',
        why:
          'O PHP recomenda um post_max_size baixo como medida provisória: reduz a quantidade de dados ' +
          'multipart que o analisador processa antes de a memória se poder esgotar. Deve complementar-se ' +
          'com limites de tamanho no servidor web ou proxy (client_max_body_size, LimitRequestBody), já que ' +
          'um pedido sem Content-Length utilizável pode contornar a verificação inicial de post_max_size.',
        caveat: 'Ajuste o valor ao máximo de que a sua aplicação realmente precisa; 8M é o valor predefinido do PHP. Deve ser maior ou igual a upload_max_filesize.',
        details: { add: 'Não está definida (predefinição 8M). Convém defini-la explicitamente.', change: 'O valor atual {value} ({bytes}) excede o máximo recomendado de 8M.' },
      },
      upload_max_filesize: {
        category: 'Limites de tamanho do pedido',
        why:
          'Limita o tamanho de cada ficheiro carregado e, com isso, o trabalho do analisador RFC 1867 por ' +
          'pedido. Faz parte dos limites de tamanho que o PHP aconselha enquanto não for possível atualizar.',
        caveat: 'Ajuste o valor à necessidade real da aplicação; 2M é o valor predefinido do PHP.',
        details: { add: 'Não está definida (predefinição 2M). Convém defini-la explicitamente.', change: 'O valor atual {value} ({bytes}) excede o máximo recomendado de 2M.' },
      },
      max_file_uploads: {
        category: 'Limites de tamanho do pedido',
        why:
          'As provas de conceito publicadas usam pedidos multipart com um grande número de campos de ' +
          'ficheiro (mesmo vazios) para forçar o esgotamento da memória sem exceder os limites de tamanho. ' +
          'Limitar o número de ficheiros por pedido reduz esse vetor.',
        caveat: 'Baixe o valor tanto quanto a aplicação permitir (p. ex. 5 se só se carrega um ficheiro de cada vez).',
        details: { add: 'Não está definida (predefinição 20). Convém defini-la explicitamente e baixá-la se possível.', change: 'O valor atual {value} excede o máximo recomendado de 20.' },
      },
      max_input_vars: {
        category: 'Limites de tamanho do pedido',
        why:
          'Limita o número de variáveis de entrada (campos do formulário multipart) que o PHP aceita antes ' +
          'de interromper o pedido, reduzindo o trabalho do analisador por pedido.',
        caveat: 'Medida de reforço geral, não citada expressamente no aviso oficial. 1000 é o valor predefinido do PHP; alguns CMS exigem valores superiores.',
        details: { info: 'Não está definida (predefinição 1000). Adicionada comentada como referência.', change: 'O valor atual {value} excede o valor predefinido de 1000.' },
      },
      fatal_error_backtraces: {
        category: 'Mitigação recomendada pelo PHP (apenas PHP 8.5)',
        why:
          'No PHP 8.5 o backtrace gerado num erro fatal é uma das vias confirmadas da CVE-2026-109619 ' +
          '(use-after-free do backtrace + confusão de tipos no OPcache). Desativá-lo fecha essa via concreta.',
        caveat:
          'A diretiva só existe no PHP 8.5; as versões anteriores ignoram-na (e emitem um aviso no arranque ' +
          'se for definida com php_admin_value). Só bloqueia a via do backtrace, não outras variantes.',
        details: {
          skip: 'Só se aplica ao PHP 8.5.',
          add: 'Não está definida; o valor predefinido na 8.5 é On.',
          info: 'Só se aplica se usar PHP 8.5. Adicionada comentada como referência.',
          change: 'Está ativada ({value}).',
        },
      },
      file_uploads: {
        category: 'Redução de superfície (opcional)',
        why:
          'Se a aplicação não precisar de carregar ficheiros, desativar file_uploads elimina o processamento ' +
          'de ficheiros RFC 1867 (os campos de ficheiro são descartados).',
        caveat:
          'OPCIONAL: quebra qualquer carregamento de ficheiros. O PHP continua a analisar os campos normais ' +
          'de um formulário multipart, pelo que NÃO elimina por completo o caminho vulnerável. Avalie se a sua ' +
          'aplicação pode prescindir dos carregamentos durante a janela de atualização.',
        details: {
          infoAbsent: 'Não está definida (predefinição On). Adicionada comentada para que decida.',
          infoOn: 'Os carregamentos estão ativados. É adicionada uma sugestão comentada para que decida.',
        },
      },
      expose_php: {
        category: 'Reforço geral',
        why:
          'Oculta o cabeçalho X-Powered-By com a versão exata do PHP. Os scanners massivos do PHP2Shell ' +
          'usam-no para localizar instalações vulneráveis.',
        caveat: 'Não mitiga a vulnerabilidade; apenas dificulta a identificação da versão.',
        details: { add: 'Não está definida (predefinição On).', change: 'Está ativada ({value}).' },
      },
    },
  };
});
