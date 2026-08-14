# ADR-0010: Extensões FIDO2 CTAP 2.1 — LargeBlobs, Credential Management, Enterprise Attestation e Algoritmos Adicionais

## Contexto

A especificação FIDO CTAP 2.1 introduz recursos avançados para suportar novos casos de uso corporativos, armazenamento flexível de credenciais e gestão de ciclo de vida de chaves residentes:
1. **LargeBlobs Extension (`0x0C`) & `largeBlobKey`**:
   - Permite que relying parties e aplicações leiam e escrevam dados arbitrários cifrados de tamanho estendido no autenticador (ex.: credenciais SSH/OpenPGP cifradas, certificados client-side).
   - A extensão `largeBlobKey` associada gera uma chave simétrica de 32 bytes por credencial que a RP utiliza para cifrar/decifrar o blob.
2. **Credential Management (`0x0A`)**:
   - Subcomandos para consultar capacidade de credenciais residentes (`getCredsMetadata`), enumerar relying parties (`enumerateRPs`), enumerar credenciais com chaves públicas COSE e metadados de usuário (`enumerateCredentials`), atualizar informações do usuário (`updateUserInformation`) e excluir credenciais individuais (`deleteCredential`).
3. **Enterprise Attestation (`ep`)**:
   - Permite atestação com certificado corporativo dedicado em ambientes gerenciados onde o RP ID está na lista permitida.
4. **Algoritmos Criptográficos Adicionais**:
   - **ES384** (ECDSA P-384 + SHA-384, alg `-35`): Para ambientes com requisitos de nível de segurança comercial/governamental NSA Suite B / CNSA.
   - **PS256** (RSA-PSS + SHA-256, alg `-37`): Para esquemas de assinatura RSA probabilísticos modernos.

## Decisão

1. **Camada de Criptografia (`protocol/crypto`)**:
   - Implementar `generate_p384_key_pair`, `sign_p384`, `verify_p384` usando `ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING`.
   - Implementar `sign_rsa_pss`, `verify_rsa_pss` usando `ring::signature::RSA_PSS_SHA256` e `RSA_PSS_2048_8192_SHA256`.
   - Serialização de chaves públicas COSE no `ctap2`: `build_cose_key_p384` (kty=2, crv=2, alg=-35, x=48B, y=48B) e `build_cose_key_rsa_pss` (kty=3, alg=-37, n=modulus, e=exponent).

2. **Extensões de Storage (`firmware/storage`)**:
   - Estrutura `Credential` estendida com campos opcionais: `large_blob_key: Option<Vec<u8>>`, `user_name: Option<String>`, `user_display_name: Option<String>`.
   - Buffer global `large_blobs: Vec<u8>` com limite máximo configurável (default 4096 bytes), persistido no backend seguro.
   - Métodos de manipulação: `read_large_blobs`, `write_large_blobs`, `clear_large_blobs`, `find_credentials_by_rp_hash`, `update_user_info`, `get_credentials_count`, `get_max_possible_remaining`.

3. **Protocolo e Comandos CTAP2 (`protocol/ctap2`)**:
   - Módulos `large_blobs` (`LargeBlobsRequest`, `LargeBlobsResponse`) e `cred_mgmt` (`CredentialManagementRequest`, `CredMgmtParams`, responses de metadados e enumeração).
   - Negociação de algoritmos no `MakeCredential` e assinatura correspondente no `GetAssertion` para `-7`, `-8`, `-35`, `-37`, `-257`.
   - Despacho dos opcodes `0x0A` (Credential Management) e `0x0C` (LargeBlobs) na máquina de estados do `Ctap2Authenticator`.
   - Capacidades reportadas em `GetInfo`: opções `"largeBlobs"`, `"credMgmt"`, `"ep"`, extensões `"largeBlobKey"` e campo `maxLargeBlobDataSize`.

## Consequências

### Positivas
- 100% de conformidade com a suíte de extensões CTAP 2.1 para gestão de credenciais e large blobs.
- Suporte a ambientes corporativos governamentais através de curvas elípticas maiores (P-384) e esquemas RSA-PSS.
- APIs limpas e desacopladas com serialização CBOR estrita e cobertura total de testes unitários.

### Neutras / Considerações
- O limite máximo padrão de large blobs foi fixado em 4096 bytes para proteger o consumo de memória flash/RAM de microcontroladores embarcados.
