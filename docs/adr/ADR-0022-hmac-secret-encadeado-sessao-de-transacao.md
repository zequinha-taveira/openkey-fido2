# ADR-0022: hmac-secret Encadeado — Sessão de Transação

Status: accepted
Data: 2026-08-22

## Contexto

A extensão `hmac-secret` (CTAP 2.1 §12.5) era processada apenas na asserção
inicial do GetAssertion. O `protocol/ctap2/src/hmac_secret.rs` consumia a
`PinAgreementKey` anunciada no getKeyAgreement (uso único, §6.5.5.4), derivava
o segredo compartilhado, decifra os salts e **descartava** todo o material ao
fim da asserção. O GetNextAssertion não emitia saída da extensão, quebrando
plataformas que fazem login multi-conta com hmac-secret na segunda asserção da
cadeia (dívida registrada no `TODO.md`, seção "Dívidas residuais conhecidas").

Alternativas consideradas:

1. **Manter a `PinAgreementKey` viva entre comandos** e rederivar o segredo a
   cada GetNextAssertion — rejeitada: amplia a superfície de ataque (a chave
   privada efêmera sobreviveria além de uma transação, contrariando a regra de
   uso único do §6.5.5.4) e exigiria repetir a verificação `saltAuth` sem
   material novo da plataforma.
2. **Cachear apenas o segredo compartilhado** e recifrar os salts por asserção
   — rejeitada: os salts chegam cifrados uma única vez no GetAssertion; cada
   saída encadeada é `HMAC-SHA-256(CredRandom_da_credencial, salt_i)`, logo os
   salts decifrados precisam sobreviver às asserções seguintes. Guardar só o
   segredo obrigaria a persistir também o `saltEnc` original ou a redecifrá-lo,
   mantendo mais material cifrado em memória pelo mesmo período.
3. **Reprocessar a extensão inteira por asserção encadeada** — inviável: o
   GetNextAssertion não carrega mapa de extensões; o §12.5 define que a saída
   vale para todas as asserções da transação iniciada pelo getAssertion.

Restrições técnicas: sem `unsafe`; nonces via `SystemRandom`; material
sensível zeroizado (`Zeroizing`); nada persistido em storage.

## Decisão

Introduzir uma **sessão de transação hmac-secret**, volátil e limitada a uma
transação de user presence:

- Novo tipo `HmacSecretSession` (`protocol/ctap2/src/hmac_secret.rs`) com
  `shared_secret: Zeroizing<Vec<u8>>` (32 bytes no protocolo PIN/UV 1, 64 no
  protocolo 2), `pin_protocol: u8` e `salts: Zeroizing<Vec<u8>>` (plaintext dos
  salts, 32 ou 64 bytes). `Debug` redigido via `Zeroizing`.
- Na asserção inicial com `hmac-secret`, `begin_session` executa exatamente o
  fluxo atual (consome a chave de acordo, deriva o segredo, verifica
  `saltAuth`, decifra/valida os salts) e a sessão resultante é retida no novo
  campo `hmac_secret_session` do `Ctap2Authenticator`. Se a credencial inicial
  não tem CredRandom, a extensão é ignorada como hoje e nenhuma sessão nasce.
- Em cada GetNextAssertion cuja requisição inicial pediu a extensão,
  `session_output` calcula `HMAC(CredRandom_da_credencial_assinalada, salt_i)`
  usando a MESMA seleção UV da asserção inicial (espelhada no estado) e cifra
  sob o segredo retido com IV fresco via `SystemRandom` (protocolo 1 mantém o
  IV zero definido pela própria especificação §6.5.6). A forma do mapa de
  extensões é idêntica à da asserção inicial.
- A sessão vive **apenas em memória** e é limpa em toda fronteira:
  - qualquer comando CTAP2 diferente de GetNextAssertion (gancho no
    `process_command`);
  - fim da cadeia (última asserção servida ou exaustão com erro);
  - transação de asserção única (a sessão nem sobrevive ao próprio
    GetAssertion);
  - Reset;
  - nova GetAssertion com a extensão inicia uma sessão fresca.
  Nunca é persistida em storage. O tempo de vida justifica-se porque o segredo
  já existe em memória durante o processamento da asserção inicial; a sessão
  apenas estende esse intervalo até o fim da cadeia, com `Zeroizing` apagando
  o material no drop.

Correção habilitante: `ExtensionOutputs` (respostas) não decodificava mapas de
extensão parciais — faltava o `#[serde(default)]` explícito que a própria
struct de entrada documenta como obrigatório ("campos opcionais exigem
`default` quando usam helper serde"). Sem isso, qualquer resposta com apenas
`"hmac-secret"` falhava `decode_cbor` com `InvalidCbor`.

## Consequências

Positivas:

- Login multi-conta com hmac-secret funciona: cada asserção encadeada carrega
  a saída derivada do CredRandom da própria credencial, sob o mesmo segredo da
  plataforma.
- A chave de acordo P-256 continua de uso único; nenhum material privado extra
  sobrevive à transação.
- Fronteiras de limpeza explícitas e testáveis (comando intermediário, Reset,
  exaustão, asserção única).

Negativas / compensações aceitas:

- Material sensível (segredo compartilhado + salts) permanece em memória pela
  duração da cadeia, não só de uma asserção. Mitigações: `Zeroizing` no drop,
  `Debug` redigido, ausência de persistência, limpeza em toda fronteira de
  comando e limites da própria transação (uma cadeia exige presença contínua
  da plataforma).
- Um GetNextAssertion após comando intermediário sai SEM a saída da extensão
  (a sessão morreu), embora o encadeamento de asserções continue — coerente
  com a transação ter sido interrompida.
- Alternativa 1 (chave viva entre comandos) foi rejeitada justamente por ter
  superfície de ataque maior: manteria chave privada efêmera além da transação
  e permitiria rederivações sem prova renovada da plataforma.
