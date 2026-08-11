use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use authenticator::EmbeddedAuthenticator;
use board_generic::BoardDefinition;

/// Autenticador virtual FIDO2 em processo, ligado ao mesmo núcleo Rust que
/// compila para firmware (`EmbeddedAuthenticator`). Fala CTAP2 real sobre
/// CBOR via `process_command`.
#[pyclass(name = "VirtualAuthenticator", module = "openkey_core")]
pub struct VirtualAuthenticator {
    inner: EmbeddedAuthenticator,
}

#[pymethods]
impl VirtualAuthenticator {
    /// Cria um autenticador virtual a partir de um board "virtual".
    ///
    /// Args:
    ///     aaguid (bytes, opcional): 16 bytes; default é tudo zero.
    ///     product_name (str, opcional): nome do board exibido no GetInfo.
    #[new]
    #[pyo3(signature = (aaguid=None, product_name=None))]
    fn new(aaguid: Option<Vec<u8>>, product_name: Option<String>) -> PyResult<Self> {
        let aaguid: [u8; 16] = match aaguid {
            Some(bytes) => bytes.try_into().map_err(|_| {
                PyValueError::new_err("aaguid deve ter exatamente 16 bytes")
            })?,
            None => [0u8; 16],
        };
        let board = BoardDefinition::new(
            match product_name {
                Some(name) => Box::leak(name.into_boxed_str()),
                None => "openkey-virtual",
            },
            aaguid,
        );
        let inner = EmbeddedAuthenticator::new_with_board(&board).map_err(|e| {
            PyValueError::new_err(format!("falha ao inicializar o autenticador: {e}"))
        })?;
        Ok(Self { inner })
    }

    /// Executa um comando CTAP2 (wire format) contra o núcleo Rust.
    ///
    /// Args:
    ///     cmd (int): código do comando CTAP2 (ex.: 0x01 makeCredential).
    ///     data (bytes): parâmetros do comando em CBOR.
    ///
    /// Returns:
    ///     (status, response): `status` é 0 (CTAP2_SUCCESS) em sucesso e, em
    ///     erro, o código CTAP2 correspondente; `response` são os bytes CBOR
    ///     da resposta (vazio em erro).
    fn process_command(&mut self, cmd: u8, data: &[u8]) -> (u32, Vec<u8>) {
        match self.inner.process_command(cmd, data.to_vec()) {
            Ok(response) => (0, response),
            Err(error) => (error.as_u8() as u32, Vec::new()),
        }
    }
}

#[pymodule]
fn openkey_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VirtualAuthenticator>()?;
    Ok(())
}
