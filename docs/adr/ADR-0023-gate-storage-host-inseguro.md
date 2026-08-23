# ADR-0023: Gate Explícito para Storage de Host Inseguro

Status: accepted
Data: 2026-08-22

## Contexto

O construtor público
`EmbeddedAuthenticator::new_with_storage_path(PathBuf, DeviceProfile)`
(`firmware/authenticator/src/authenticator.rs`) persiste credenciais em
arquivo local com a chave-mestra derivada do próprio caminho:
`SHA-256(caminho)` (`derive_key_from_path`). O backend de storage usa cifra
real em repouso (ChaCha20-Poly1305), porém a chave é publicamente derivável —
qualquer leitor local que conheça o caminho do arquivo rederivá-la e decifra
todas as credenciais. A confidencialidade efetiva se reduz a ofuscação.

O problema não era o comportamento em si (adequado ao simulador e a testes,
onde reabrir o mesmo caminho precisa recuperar as credenciais), mas sua
**disponibilidade silenciosa na API de produto**: `EmbeddedAuthenticator` é a
API final para integradores, e nada no call site indicava que o storage era
inseguro. Um integrador podia enviar credenciais "criptografadas" com uma
chave derivável sem nunca confrontar a limitação.

Restrições técnicas: sem `unsafe`; API interna do workspace (todos os
callers são atualizados na mesma mudança); comportamento de derivação deve
permanecer byte-idêntico para não quebrar a persistência E2E existente.

Alternativas consideradas:

1. **Manter `new_with_storage_path` com doc comment de aviso** — rejeitada:
   documentação não impede uso; o risco continuava invisível em code review.
2. **Feature flag** (ex.: `insecure-host-storage`) — rejeitada: flags são
   invisíveis no call site; o binário compilado não carrega a decisão, e o
   reviewer precisa reconstruir mentalmente o conjunto de features para
   avaliar o risco.
3. **Remover o caminho host inteiro da API** — rejeitado nesta etapa: simulador
   e testes E2E dependem da persistência em arquivo; remoção exigiria um
   substituto com secure element, fora do escopo.

## Decisão

Introduzir um **tipo marcador explícito**, `InsecureHostStorage`
(`firmware/authenticator/src/authenticator.rs`):

- Estrutura pública com campo privado `path: PathBuf` e construtor
  `InsecureHostStorage::new(path)`. A doc comment declara o risco: a chave é
  derivada do caminho, qualquer leitor local pode decifrar tudo, uso restrito
  a simulador/testes, produto real exige secure element.
- `EmbeddedAuthenticator::new_with_insecure_host_storage(storage:
  InsecureHostStorage, profile)` substitui `new_with_storage_path` **sem
  manter o nome antigo**: a assinatura só aceita o marcador. Todo call site
  passa a ler
  `EmbeddedAuthenticator::new_with_insecure_host_storage(InsecureHostStorage::new(path),
  profile)`, auto-documentado.
- `derive_key_from_path` permanece privado e usado apenas dentro do caminho
  gated; derivação e backend (`FileStorageBackend`) são byte-idênticos ao
  anterior, então a persistência existente continua válida.
- Callers atualizados na mesma mudança: `simulator/src/main.rs` (construção
  inicial com `--storage-path` e reinício no Reset).

Para produto real, o integrador deve injetar crypto/storage próprios com
chave de secure element (o ponto de composição interno
`from_profile_and_storage` já separa essas dependências); nenhum construtor
público novo de produto é introduzido aqui — isso fica registrado como
trabalho futuro no `TODO.md`.

## Consequências

Positivas:

- Misuso visível em code review: todo uso de chave derivável exige escrever
  `InsecureHostStorage` no call site — impossível usar a API por engano ou
  desconhecimento.
- API auto-documentada: rustdoc do tipo marcador carrega o aviso completo
  onde o integrador está codando.
- Comportamento preservado: simulador, testes Rust e E2E Python de
  persistência seguem passando sem alteração semântica.

Negativas / compensações aceitas:

- Renome quebra a API interna do workspace; mitigado atualizando todos os
  callers na mesma mudança (a API é workspace-interna, sem consumidores
  externos conhecidos).
- O marcador não impede tecnicamente o uso indevido — quem insistir pode
  usá-lo em produção. A defesa é processual (visibilidade em review), não
  técnica; uma barreira dura exigiria a alternativa 3, adiada até existir o
  caminho de secure element.
- Continua pendente: construtor público para produto com injeção de
  `CryptoEngine`/backend de secure element (dívida registrada no `TODO.md`).
