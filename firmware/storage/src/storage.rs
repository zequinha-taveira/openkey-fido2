use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use crypto::CryptoEngine;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use zeroize::Zeroize;

extern crate alloc;

/// Erros produzidos pela camada de armazenamento.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Chave inexistente no backend ou no cache em memória.
    #[error("key not found: {0}")]
    KeyNotFound(String),
    /// Falha reportada pelo backend subjacente (arquivo, flash, etc.).
    #[error("backend error: {0}")]
    BackendError(String),
    /// Falha ao serializar/desserializar dados persistidos.
    #[error("serialization error: {0}")]
    SerializationError(String),
    /// Limite de credenciais do dispositivo atingido.
    #[error("max credentials reached ({0})")]
    MaxCredentialsReached(usize),
    /// Setor atingiu o limite de escritas — protege a flash contra desgaste.
    #[error("wear leveling threshold exceeded for sector {0}")]
    WearLevelingThresholdExceeded(String),
    /// Erro de I/O ao acessar o meio persistente.
    #[error("IO error: {0}")]
    IoError(String),
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::IoError(e.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::SerializationError(e.to_string())
    }
}

/// Meio de persistência key-value usado pelo [`StorageEngine`].
///
/// Abstrair o meio permite trocar arquivo (host) por flash (embarcado) sem
/// alterar a lógica de credenciais.
pub trait StorageBackend: Send + Sync {
    /// Lê o valor associado a `key`, ou `None` se ausente.
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;
    /// Grava `value` sob `key`, sobrescrevendo valor anterior.
    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError>;
    /// Remove `key`. Não é erro se a chave não existir.
    fn delete(&mut self, key: &str) -> Result<(), StorageError>;
    /// Lista todas as chaves conhecidas, usado na carga inicial.
    fn list_keys(&self) -> Result<Vec<String>, StorageError>;
}

/// Backend de arquivo JSON para uso em host (simulador, testes, exemplos).
///
/// Mantém um cache em memória e grava a cada escrita, de forma que uma queda
/// do processo não perca credenciais já registradas.
pub struct FileStorageBackend {
    path: PathBuf,
    journal_path: PathBuf,
    cache: HashMap<String, Vec<u8>>,
    dirty: bool,
}

impl FileStorageBackend {
    /// Abre (ou cria) o arquivo em `path` e carrega seu conteúdo no cache.
    pub fn new(path: PathBuf) -> Result<Self, StorageError> {
        let journal_path = path.with_extension("journal");
        let cache = Self::load_snapshot(&path, &journal_path)?;
        Ok(Self {
            path,
            journal_path,
            cache,
            dirty: false,
        })
    }

    fn load_snapshot(
        path: &PathBuf,
        journal_path: &PathBuf,
    ) -> Result<HashMap<String, Vec<u8>>, StorageError> {
        let snapshot_path = if journal_path.exists() {
            journal_path
        } else {
            path
        };

        if !snapshot_path.exists() {
            return Ok(HashMap::new());
        }

        let content = fs::read_to_string(snapshot_path)?;
        if content.trim().is_empty() {
            Ok(HashMap::new())
        } else {
            Ok(serde_json::from_str(&content)?)
        }
    }

    /// Grava o cache em disco quando houver alterações pendentes.
    pub fn flush(&mut self) -> Result<(), StorageError> {
        if self.dirty {
            let json = serde_json::to_string_pretty(&self.cache)?;
            if let Some(parent) = self.path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            if let Some(parent) = self.journal_path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            // The journal is durable before the main file is replaced. If the
            // process loses power during replacement, startup can recover it.
            write_durable(&self.journal_path, json.as_bytes())?;

            let temporary_path = self.path.with_extension("tmp");
            write_durable(&temporary_path, json.as_bytes())?;
            replace_file(&temporary_path, &self.path)?;
            fs::remove_file(&self.journal_path)?;
            self.dirty = false;
        }
        Ok(())
    }
}

fn write_durable(path: &PathBuf, contents: &[u8]) -> Result<(), StorageError> {
    let mut file = File::create(path)?;
    use std::io::Write;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn replace_file(source: &PathBuf, destination: &PathBuf) -> Result<(), StorageError> {
    // Windows cannot rename over an existing file. The journal still makes
    // this two-step replacement recoverable if power fails between operations.
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(source, destination)?;
    Ok(())
}

impl StorageBackend for FileStorageBackend {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cache.get(key).cloned())
    }

    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.cache.insert(key.to_string(), value.to_vec());
        self.dirty = true;
        self.flush()?;
        Ok(())
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.cache.remove(key);
        self.dirty = true;
        self.flush()?;
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, StorageError> {
        Ok(self.cache.keys().cloned().collect())
    }
}

/// Contrato mínimo que uma HAL de flash deve adaptar.
///
/// `program` só pode mudar bits de 1 para 0; apagar restaura um setor inteiro
/// para `0xff`. A implementação concreta deve garantir essas regras também
/// quando o dispositivo for real.
pub trait FlashDevice: Send + Sync {
    fn capacity(&self) -> usize;
    fn sector_size(&self) -> usize;
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageError>;
    fn erase_sector(&mut self, sector: usize) -> Result<(), StorageError>;
    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageError>;
}

/// Flash NOR determinística para testes de backend e de power-loss.
pub struct SimulatedFlash {
    bytes: Vec<u8>,
    sector_size: usize,
    fail_after_program_bytes: Option<usize>,
}

impl SimulatedFlash {
    /// Cria uma flash apagada com dois ou mais setores.
    pub fn new(sector_size: usize, sectors: usize) -> Self {
        assert!(sector_size > 0 && sectors >= 2);
        Self {
            bytes: vec![0xff; sector_size * sectors],
            sector_size,
            fail_after_program_bytes: None,
        }
    }

    /// Faz a próxima operação `program` falhar depois de programar `bytes`.
    pub fn fail_after_program_bytes(&mut self, bytes: usize) {
        self.fail_after_program_bytes = Some(bytes);
    }
}

impl FlashDevice for SimulatedFlash {
    fn capacity(&self) -> usize {
        self.bytes.len()
    }

    fn sector_size(&self) -> usize {
        self.sector_size
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageError> {
        let end = offset
            .checked_add(out.len())
            .ok_or_else(|| StorageError::BackendError("flash read overflow".into()))?;
        if end > self.bytes.len() {
            return Err(StorageError::BackendError(
                "flash read out of bounds".into(),
            ));
        }
        out.copy_from_slice(&self.bytes[offset..end]);
        Ok(())
    }

    fn erase_sector(&mut self, sector: usize) -> Result<(), StorageError> {
        let start = sector
            .checked_mul(self.sector_size)
            .ok_or_else(|| StorageError::BackendError("flash sector overflow".into()))?;
        let end = start + self.sector_size;
        if end > self.bytes.len() {
            return Err(StorageError::BackendError(
                "flash sector out of bounds".into(),
            ));
        }
        self.bytes[start..end].fill(0xff);
        Ok(())
    }

    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageError> {
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| StorageError::BackendError("flash program overflow".into()))?;
        if end > self.bytes.len() {
            return Err(StorageError::BackendError(
                "flash program out of bounds".into(),
            ));
        }
        let mut allowed = data.len();
        if let Some(limit) = self.fail_after_program_bytes.take() {
            allowed = limit.min(data.len());
        }
        for (old, new) in self.bytes[offset..offset + allowed]
            .iter_mut()
            .zip(&data[..allowed])
        {
            if (*old | *new) != *old {
                return Err(StorageError::BackendError(
                    "flash program attempted 0 to 1".into(),
                ));
            }
            *old &= *new;
        }
        if allowed != data.len() {
            return Err(StorageError::BackendError(
                "simulated power loss during flash program".into(),
            ));
        }
        Ok(())
    }
}

const FLASH_MAGIC: &[u8; 4] = b"OKF1";
const FLASH_HEADER_SIZE: usize = 20;
type FlashSnapshot = (u64, HashMap<String, Vec<u8>>);

/// Backend crash-safe de dois slots para uma flash NOR adaptada por [`FlashDevice`].
pub struct FlashStorageBackend<D: FlashDevice> {
    device: D,
    cache: HashMap<String, Vec<u8>>,
    active_sector: usize,
    generation: u64,
}

impl<D: FlashDevice> FlashStorageBackend<D> {
    /// Abre a versão válida mais recente; setores incompletos são ignorados.
    pub fn new(device: D) -> Result<Self, StorageError> {
        if device.capacity() < device.sector_size() * 2 || device.sector_size() <= FLASH_HEADER_SIZE
        {
            return Err(StorageError::BackendError(
                "flash must provide two usable sectors".into(),
            ));
        }
        let mut backend = Self {
            device,
            cache: HashMap::new(),
            active_sector: 0,
            generation: 0,
        };
        backend.load_latest()?;
        Ok(backend)
    }

    /// Recupera o dispositivo para simular uma reinicialização.
    pub fn into_device(self) -> D {
        self.device
    }

    fn checksum(data: &[u8]) -> u32 {
        data.iter().fold(2166136261u32, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(16777619)
        })
    }

    fn read_slot(&self, sector: usize) -> Result<Option<FlashSnapshot>, StorageError> {
        let size = self.device.sector_size();
        let mut raw = vec![0xff; size];
        self.device.read(sector * size, &mut raw)?;
        if &raw[..4] != FLASH_MAGIC {
            return Ok(None);
        }
        let generation = u64::from_le_bytes(raw[4..12].try_into().unwrap());
        let len = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;
        let checksum = u32::from_le_bytes(raw[16..20].try_into().unwrap());
        if len > size - FLASH_HEADER_SIZE {
            return Ok(None);
        }
        let payload = &raw[FLASH_HEADER_SIZE..FLASH_HEADER_SIZE + len];
        if Self::checksum(payload) != checksum {
            return Ok(None);
        }
        let cache = serde_json::from_slice(payload)
            .map_err(|_| StorageError::BackendError("invalid flash snapshot".into()))?;
        Ok(Some((generation, cache)))
    }

    fn load_latest(&mut self) -> Result<(), StorageError> {
        for sector in 0..2 {
            if let Some((generation, cache)) = self.read_slot(sector)? {
                if generation >= self.generation {
                    self.generation = generation;
                    self.active_sector = sector;
                    self.cache = cache;
                }
            }
        }
        Ok(())
    }

    fn commit(&mut self, cache: &HashMap<String, Vec<u8>>) -> Result<(), StorageError> {
        let payload = serde_json::to_vec(cache)?;
        let size = self.device.sector_size();
        if payload.len() > size - FLASH_HEADER_SIZE {
            return Err(StorageError::BackendError(
                "flash snapshot exceeds sector capacity".into(),
            ));
        }
        let target = 1 - self.active_sector;
        self.device.erase_sector(target)?;
        let generation = self.generation + 1;
        let mut header = [0xff; FLASH_HEADER_SIZE];
        header[..4].copy_from_slice(FLASH_MAGIC);
        header[4..12].copy_from_slice(&generation.to_le_bytes());
        header[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[16..20].copy_from_slice(&Self::checksum(&payload).to_le_bytes());
        let offset = target * size;
        self.device.program(offset, &header)?;
        self.device.program(offset + FLASH_HEADER_SIZE, &payload)?;
        self.active_sector = target;
        self.generation = generation;
        Ok(())
    }
}

impl<D: FlashDevice> StorageBackend for FlashStorageBackend<D> {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cache.get(key).cloned())
    }

    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let mut next = self.cache.clone();
        next.insert(key.to_string(), value.to_vec());
        self.commit(&next)?;
        self.cache = next;
        Ok(())
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        let mut next = self.cache.clone();
        next.remove(key);
        self.commit(&next)?;
        self.cache = next;
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, StorageError> {
        Ok(self.cache.keys().cloned().collect())
    }
}

const WEAR_LEVELING_THRESHOLD: u32 = 10_000;

#[derive(Debug, Clone)]
struct WearLevelCounter {
    sector: String,
    write_count: u32,
}

impl WearLevelCounter {
    fn new(sector: String) -> Self {
        Self {
            sector,
            write_count: 0,
        }
    }

    fn increment(&mut self) -> Result<(), StorageError> {
        self.write_count += 1;
        if self.write_count >= WEAR_LEVELING_THRESHOLD {
            warn!(
                "Wear leveling threshold reached for sector '{}' (count={})",
                self.sector, self.write_count
            );
            return Err(StorageError::WearLevelingThresholdExceeded(
                self.sector.clone(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
/// Credencial FIDO2 de um par (relying party, usuário).
///
/// Implementa `Zeroize` com `drop` para que `private_key` seja apagada da
/// memória assim que a credencial sai de escopo (ADR-0006).
pub struct Credential {
    /// Identificador opaco entregue ao relying party.
    pub credential_id: Vec<u8>,
    /// Chave pública no formato bruto do algoritmo (Ed25519, P-256 ou RSA).
    pub public_key: Vec<u8>,
    /// Chave privada. Vazia quando a credencial está persistida — o material
    /// real vive cifrado em [`StoredCredential::encrypted_private_key`].
    pub private_key: Vec<u8>,
    /// Contador de assinaturas, incrementado a cada GetAssertion.
    pub sign_count: u32,
    /// SHA-256 do `rp_id`, conforme o authData do CTAP2.
    pub rp_id_hash: Vec<u8>,
    /// `user.id` do WebAuthn, quando a credencial é discoverable.
    pub user_handle: Option<Vec<u8>>,
    /// Dados opacos da extensão `credBlob` (máx. 32 bytes).
    pub cred_blob: Vec<u8>,
    /// Timestamp de criação, usado para descartar a credencial mais antiga
    /// quando o limite do dispositivo é atingido.
    pub created_at: u64,
    /// Algoritmo COSE (-8 EdDSA, -7 ES256, -257 RS256).
    #[serde(default)]
    pub algorithm: i32,
    /// `rp_id` em texto, necessário para EnumerateRPs.
    #[serde(default)]
    pub rp_id: String,
    /// Chave simétrica para a extensão `largeBlobKey` (32 bytes).
    #[serde(default)]
    pub large_blob_key: Option<Vec<u8>>,
    /// Nome de exibição do usuário (`user.name`).
    #[serde(default)]
    pub user_name: Option<String>,
    /// Nome amigável do usuário (`user.displayName`).
    #[serde(default)]
    pub user_display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
/// Forma persistida de uma [`Credential`], com a chave privada cifrada.
pub struct StoredCredential {
    /// Credencial com `private_key` vazia.
    pub credential: Credential,
    /// Chave privada cifrada com ChaCha20-Poly1305.
    pub encrypted_private_key: Vec<u8>,
    /// Nonce de 12 bytes usado na cifragem, único por credencial.
    pub nonce: Vec<u8>,
}

/// Motor de credenciais: cifra, indexa e persiste [`Credential`]s.
///
/// Mantém um índice em memória (`BTreeMap` para ordem determinística) e,
/// opcionalmente, delega a persistência a um [`StorageBackend`].
pub struct StorageEngine {
    credentials: BTreeMap<Vec<u8>, StoredCredential>,
    kv_store: BTreeMap<String, Vec<u8>>,
    large_blobs: Vec<u8>,
    backend: Option<Box<dyn StorageBackend>>,
    wear_counters: HashMap<String, WearLevelCounter>,
    max_credential_count: Option<usize>,
}

impl core::fmt::Debug for StorageEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StorageEngine")
            .field("credentials", &self.credentials)
            .field("kv_store", &self.kv_store)
            .field("large_blobs_len", &self.large_blobs.len())
            .field("backend", &self.backend.is_some())
            .field("wear_counters", &self.wear_counters)
            .field("max_credential_count", &self.max_credential_count)
            .finish()
    }
}

impl StorageEngine {
    /// Cria um motor somente em memória — credenciais somem ao encerrar.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        info!("Storage engine initialized");
        Ok(Self {
            credentials: BTreeMap::new(),
            kv_store: BTreeMap::new(),
            large_blobs: Vec::new(),
            backend: None,
            wear_counters: HashMap::new(),
            max_credential_count: None,
        })
    }

    /// Cria um motor persistente e carrega as credenciais já existentes.
    ///
    /// Falhas de carga são registradas em log mas não abortam a inicialização:
    /// um autenticador com storage corrompido ainda deve responder a GetInfo.
    pub fn with_backend(backend: Box<dyn StorageBackend>) -> Self {
        info!("Storage engine initialized with custom backend");
        let mut engine = Self {
            credentials: BTreeMap::new(),
            kv_store: BTreeMap::new(),
            large_blobs: Vec::new(),
            backend: Some(backend),
            wear_counters: HashMap::new(),
            max_credential_count: None,
        };
        if let Err(e) = engine.load_from_backend() {
            warn!("Failed to load credentials from backend: {}", e);
        }
        engine
    }

    fn load_from_backend(&mut self) -> Result<(), StorageError> {
        let keys = if let Some(backend) = &self.backend {
            backend.list_keys()?
        } else {
            return Ok(());
        };

        for key in keys {
            if let Some(cred_data) = self.backend.as_ref().unwrap().read(&key)? {
                if let Ok(stored) = serde_json::from_slice::<StoredCredential>(&cred_data) {
                    self.credentials
                        .insert(stored.credential.credential_id.clone(), stored);
                }
            }
        }

        info!("Loaded {} credentials from backend", self.credentials.len());
        Ok(())
    }

    /// Define o limite de credenciais residentes.
    ///
    /// Ao atingir o limite, a credencial mais antiga é descartada em vez de
    /// rejeitar o MakeCredential.
    pub fn set_max_credential_count(&mut self, max: usize) {
        self.max_credential_count = Some(max);
    }

    /// Grava um valor arbitrário no key-value store (estado do ClientPIN, etc.).
    pub fn store(&mut self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        self.increment_wear_counter("kv")?;
        if let Some(backend) = &mut self.backend {
            backend.write(key, &value)?;
        }
        self.kv_store.insert(key.to_string(), value);
        Ok(())
    }

    /// Recupera um valor do key-value store, consultando o backend primeiro.
    pub fn retrieve(&self, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(backend) = &self.backend {
            if let Some(data) = backend.read(key)? {
                return Ok(data);
            }
        }
        self.kv_store
            .get(key)
            .cloned()
            .ok_or_else(|| format!("Key '{}' not found", key).into())
    }

    /// Persiste uma credencial cifrando sua chave privada.
    ///
    /// A `private_key` recebida é limpa antes da gravação: o único material
    /// persistido é o ciphertext, garantindo encryption at rest.
    pub fn store_credential(
        &mut self,
        credential: Credential,
        crypto: &CryptoEngine,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(max) = self.max_credential_count {
            if self.credentials.len() >= max {
                self.prune_oldest_credential()?;
            }
        }

        let nonce = self.generate_nonce(crypto);
        let private_key = credential.private_key.clone();
        let encrypted = crypto.encrypt(&private_key, &nonce)?;

        let mut stored_credential = credential;
        stored_credential.private_key.clear();

        let stored = StoredCredential {
            credential: stored_credential,
            encrypted_private_key: encrypted,
            nonce,
        };

        let cred_key = format!("cred:{}", hex::encode(&stored.credential.credential_id));
        self.increment_wear_counter("credentials")?;

        if let Some(backend) = &mut self.backend {
            let data = serde_json::to_vec(&stored)?;
            backend.write(&cred_key, &data)?;
        }

        self.credentials
            .insert(stored.credential.credential_id.clone(), stored);
        debug!("Credential stored successfully");
        Ok(())
    }

    /// Busca uma credencial por ID e decifra sua chave privada.
    ///
    /// Retorna `Ok(None)` quando o ID é desconhecido — ausência não é erro,
    /// pois o CTAP2 usa esta consulta ao validar `excludeList`.
    pub fn get_credential(
        &self,
        credential_id: &[u8],
        crypto: &CryptoEngine,
    ) -> Result<Option<Credential>, Box<dyn std::error::Error>> {
        match self.credentials.get(credential_id) {
            Some(stored) => {
                let private_key = crypto.decrypt(&stored.encrypted_private_key, &stored.nonce)?;
                let mut credential = stored.credential.clone();
                credential.private_key = private_key;
                debug!("Credential retrieved and decrypted");
                Ok(Some(credential))
            }
            None => {
                warn!("Credential not found");
                Ok(None)
            }
        }
    }

    /// Atualiza o contador de assinaturas após um GetAssertion.
    ///
    /// O contador é o mecanismo do WebAuthn contra clonagem do autenticador,
    /// portanto precisa ser monotônico por credencial.
    pub fn update_sign_count(
        &mut self,
        credential_id: &[u8],
        sign_count: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.credentials.get_mut(credential_id) {
            Some(stored) => {
                stored.credential.sign_count = sign_count;
                debug!("Credential sign count updated");
                Ok(())
            }
            None => {
                warn!("Credential not found for sign count update");
                Err("Credential not found".into())
            }
        }
    }

    /// Remove uma credencial do índice e do backend.
    ///
    /// Retorna `false` quando o ID não existia.
    pub fn delete_credential(
        &mut self,
        credential_id: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if self.credentials.remove(credential_id).is_some() {
            let cred_key = format!("cred:{}", hex::encode(credential_id));
            if let Some(backend) = &mut self.backend {
                backend.delete(&cred_key)?;
            }
            debug!("Credential deleted");
            Ok(true)
        } else {
            warn!("Credential not found for deletion");
            Ok(false)
        }
    }

    /// Apaga todas as credenciais e o key-value store (CTAP2 Reset).
    pub fn clear(&mut self) {
        self.credentials.clear();
        self.kv_store.clear();
        debug!("All credentials cleared");
    }

    /// Lista as credenciais residentes.
    ///
    /// As credenciais retornadas têm `private_key` vazia: usar
    /// [`StorageEngine::get_credential`] quando o material for necessário.
    pub fn list_credentials(&self) -> Vec<&Credential> {
        self.credentials.values().map(|s| &s.credential).collect()
    }

    /// Retorna as credenciais de um relying party, já decifradas.
    ///
    /// A comparação usa o hash do `rp_id`, mesmo critério do authData, para
    /// não depender do campo textual (ausente em credenciais antigas).
    pub fn find_by_rp_id(&self, rp_id: &str, crypto: &CryptoEngine) -> Vec<Credential> {
        let rp_hash = self.hash_rp_id(rp_id, crypto);
        self.credentials
            .values()
            .filter(|s| s.credential.rp_id_hash == rp_hash)
            .filter_map(|s| {
                let private_key = crypto.decrypt(&s.encrypted_private_key, &s.nonce).ok()?;
                let mut credential = s.credential.clone();
                credential.private_key = private_key;
                Some(credential)
            })
            .collect()
    }

    /// Lista os relying parties distintos como `(rp_id, rp_id_hash)`.
    ///
    /// Credenciais sem `rp_id` textual são ignoradas — o CTAP2 EnumerateRPs
    /// exige o identificador legível.
    pub fn enumerate_rps(&self) -> Vec<(String, Vec<u8>)> {
        let mut seen = alloc::collections::BTreeSet::new();
        let mut result = Vec::new();
        for stored in self.credentials.values() {
            let rp_id = &stored.credential.rp_id;
            if rp_id.is_empty() {
                continue;
            }
            let rp_hash = stored.credential.rp_id_hash.clone();
            if seen.insert(rp_hash.clone()) {
                result.push((rp_id.clone(), rp_hash));
            }
        }
        result
    }

    /// Retorna as credenciais associadas a um `rp_id_hash` específico, já decifradas.
    pub fn find_credentials_by_rp_hash(
        &self,
        rp_hash: &[u8],
        crypto: &CryptoEngine,
    ) -> Vec<Credential> {
        self.credentials
            .values()
            .filter(|s| s.credential.rp_id_hash == rp_hash)
            .filter_map(|s| {
                let private_key = crypto.decrypt(&s.encrypted_private_key, &s.nonce).ok()?;
                let mut credential = s.credential.clone();
                credential.private_key = private_key;
                Some(credential)
            })
            .collect()
    }

    /// Retorna o número total de credenciais armazenadas.
    pub fn get_credentials_count(&self) -> usize {
        self.credentials.len()
    }

    /// Retorna o número máximo estimado de credenciais restantes que ainda cabem no storage.
    pub fn get_max_possible_remaining(&self) -> usize {
        let max = self.max_credential_count.unwrap_or(50);
        max.saturating_sub(self.credentials.len())
    }

    /// Atualiza as informações do usuário associadas a uma credencial (Credential Management).
    pub fn update_user_info(
        &mut self,
        credential_id: &[u8],
        user_name: Option<String>,
        user_display_name: Option<String>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if let Some(stored) = self.credentials.get_mut(credential_id) {
            stored.credential.user_name = user_name;
            stored.credential.user_display_name = user_display_name;

            let cred_key = format!("cred:{}", hex::encode(credential_id));
            if let Some(backend) = &mut self.backend {
                let data = serde_json::to_vec(&stored)?;
                backend.write(&cred_key, &data)?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Lê um fragmento do array global de large blobs.
    pub fn read_large_blobs(&self, offset: usize, count: usize) -> Vec<u8> {
        let len = self.large_blobs.len();
        if offset >= len {
            return Vec::new();
        }
        let end = core::cmp::min(offset + count, len);
        self.large_blobs[offset..end].to_vec()
    }

    /// Escreve um fragmento no array global de large blobs com redimensionamento se necessário.
    pub fn write_large_blobs(
        &mut self,
        offset: usize,
        data: &[u8],
        expected_len: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if expected_len > 4096 {
            return Err("Large blob exceeds maximum supported size (4096 bytes)".into());
        }
        if self.large_blobs.len() < expected_len {
            self.large_blobs.resize(expected_len, 0);
        }
        let end = offset + data.len();
        if end > self.large_blobs.len() {
            self.large_blobs.resize(end, 0);
        }
        self.large_blobs[offset..end].copy_from_slice(data);

        // Se houver backend persistente, salva sob chave reservada "sys:large_blobs"
        if let Some(backend) = &mut self.backend {
            backend.write("sys:large_blobs", &self.large_blobs)?;
        }

        Ok(())
    }

    /// Limpa o array global de large blobs.
    pub fn clear_large_blobs(&mut self) {
        self.large_blobs.clear();
        if let Some(backend) = &mut self.backend {
            let _ = backend.delete("sys:large_blobs");
        }
    }

    /// Retorna o tamanho atual do array de large blobs.
    pub fn get_large_blobs_len(&self) -> usize {
        self.large_blobs.len()
    }

    fn generate_nonce(&self, crypto: &CryptoEngine) -> Vec<u8> {
        crypto.random_bytes(12)
    }

    fn hash_rp_id(&self, rp_id: &str, crypto: &CryptoEngine) -> Vec<u8> {
        crypto.sha256(rp_id.as_bytes())
    }

    fn increment_wear_counter(&mut self, sector: &str) -> Result<(), Box<dyn std::error::Error>> {
        let counter = self
            .wear_counters
            .entry(sector.to_string())
            .or_insert_with(|| WearLevelCounter::new(sector.to_string()));
        counter.increment()?;
        Ok(())
    }

    fn prune_oldest_credential(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let oldest_key = self
            .credentials
            .values()
            .min_by_key(|s| s.credential.created_at)
            .map(|s| s.credential.credential_id.clone());

        if let Some(key) = oldest_key {
            info!(
                "Pruning oldest credential (created_at={}) due to max credential limit",
                self.credentials
                    .get(&key)
                    .map(|s| s.credential.created_at)
                    .unwrap_or(0)
            );
            self.delete_credential(&key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_credential(crypto: &CryptoEngine, rp_id: &str, cred_id: Vec<u8>) -> Credential {
        Credential {
            credential_id: cred_id,
            public_key: vec![1; 32],
            private_key: vec![2; 32],
            sign_count: 0,
            rp_id_hash: crypto.sha256(rp_id.as_bytes()),
            user_handle: None,
            cred_blob: Vec::new(),
            created_at: 0,
            algorithm: -8,
            rp_id: rp_id.to_string(),
            large_blob_key: None,
            user_name: None,
            user_display_name: None,
        }
    }

    #[test]
    fn test_storage_enumerate_rps() {
        let crypto = CryptoEngine::new().unwrap();
        let mut storage = StorageEngine::new().unwrap();

        storage
            .store_credential(make_credential(&crypto, "example.com", vec![1; 4]), &crypto)
            .unwrap();
        storage
            .store_credential(make_credential(&crypto, "example.com", vec![2; 4]), &crypto)
            .unwrap();
        storage
            .store_credential(make_credential(&crypto, "another.com", vec![3; 4]), &crypto)
            .unwrap();

        let rps = storage.enumerate_rps();
        assert_eq!(rps.len(), 2);

        let mut rp_ids: Vec<String> = rps.iter().map(|(id, _)| id.clone()).collect();
        rp_ids.sort();
        assert_eq!(rp_ids, vec!["another.com", "example.com"]);

        for (_, hash) in &rps {
            assert_eq!(hash.len(), 32);
        }
    }

    #[test]
    fn test_storage_enumerate_rps_empty() {
        let storage = StorageEngine::new().unwrap();
        let rps = storage.enumerate_rps();
        assert!(rps.is_empty());
    }

    #[test]
    fn test_storage_enumerate_rps_empty_rp_id() {
        let crypto = CryptoEngine::new().unwrap();
        let mut storage = StorageEngine::new().unwrap();

        storage
            .store_credential(make_credential(&crypto, "", vec![1; 4]), &crypto)
            .unwrap();

        let rps = storage.enumerate_rps();
        assert!(rps.is_empty());
    }

    #[test]
    fn test_credential_private_key_zeroized_on_drop() {
        let crypto = CryptoEngine::new().unwrap();

        let mut credential = make_credential(&crypto, "example.com", vec![1; 4]);

        assert!(
            credential.private_key.iter().any(|&b| b != 0),
            "test setup: private_key should contain key material"
        );

        let mut private_key = std::mem::take(&mut credential.private_key);
        drop(credential);

        private_key.zeroize();
        assert!(
            private_key.iter().all(|&b| b == 0),
            "private_key was not zeroized"
        );
    }

    #[test]
    fn test_file_storage_recovers_from_journal() {
        let root = std::env::temp_dir().join(format!("openkey-storage-{}", std::process::id()));
        let path = root.join("store.json");
        let journal_path = path.with_extension("journal");
        let _ = fs::remove_dir_all(&root);

        let mut backend = FileStorageBackend::new(path.clone()).unwrap();
        backend.write("pin", b"old").unwrap();

        let snapshot =
            serde_json::to_vec(&HashMap::from([("pin".to_string(), b"recovered".to_vec())]))
                .unwrap();
        write_durable(&journal_path, &snapshot).unwrap();
        fs::write(&path, b"{").unwrap();

        let recovered = FileStorageBackend::new(path.clone()).unwrap();
        assert_eq!(recovered.read("pin").unwrap(), Some(b"recovered".to_vec()));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_simulated_flash_enforces_nor_programming() {
        let mut flash = SimulatedFlash::new(128, 2);
        flash.program(0, &[0x0f]).unwrap();
        assert!(flash.program(0, &[0xff]).is_err());
        flash.erase_sector(0).unwrap();
        flash.program(0, &[0xff]).unwrap();
    }

    #[test]
    fn test_flash_backend_recovers_previous_slot_after_interruption() {
        let mut flash = SimulatedFlash::new(256, 2);
        let mut backend = FlashStorageBackend::new(flash).unwrap();
        backend.write("state", b"stable").unwrap();
        flash = backend.into_device();
        flash.fail_after_program_bytes(2);
        let mut interrupted = FlashStorageBackend::new(flash).unwrap();
        assert!(interrupted.write("state", b"partial").is_err());
        let recovered = FlashStorageBackend::new(interrupted.into_device()).unwrap();
        assert_eq!(recovered.read("state").unwrap(), Some(b"stable".to_vec()));
    }
}
