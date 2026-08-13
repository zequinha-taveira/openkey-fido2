use embedded_hal::digital::InputPin;
use embedded_hal::digital::OutputPin;
use embedded_hal::i2c::I2c;
use log::{debug, info};

/// Máscara de transporte USB-CCID (smartcard).
pub const TRANSPORT_USB_CCID: u8 = 0x01;
/// Máscara de transporte USB-HID (CTAPHID).
pub const TRANSPORT_USB_HID: u8 = 0x02;
/// Máscara de transporte NFC (ISO/IEC 14443).
pub const TRANSPORT_NFC: u8 = 0x04;
/// Máscara de transporte BLE GATT.
pub const TRANSPORT_BLE: u8 = 0x08;

/// Recursos de segurança oferecidos pelo silício.
///
/// São reportados no GetInfo para que o relying party avalie o nível de
/// proteção do autenticador.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityFeatures {
    /// Boot verificado por assinatura.
    pub secure_boot: bool,
    /// Mundo seguro tipo ARM TrustZone.
    pub trust_zone: bool,
    /// Gerador de números aleatórios em hardware.
    pub hardware_rng: bool,
    /// Acelerador SHA-256 dedicado.
    pub sha256_accelerator: bool,
    /// Interface de debug permanentemente desabilitável.
    pub debug_disable: bool,
    /// Memória OTP para segredos de fábrica.
    pub otp_memory: bool,
    /// Identificador único gravado no chip.
    pub unique_id: bool,
    /// Detecção de violação física.
    pub tamper_detection: bool,
}

impl SecurityFeatures {
    /// Conjunto vazio — padrão conservador para boards genéricas.
    pub const fn none() -> Self {
        Self {
            secure_boot: false,
            trust_zone: false,
            hardware_rng: false,
            sha256_accelerator: false,
            debug_disable: false,
            otp_memory: false,
            unique_id: false,
            tamper_detection: false,
        }
    }

    /// Recursos do RP2350, o board de referência mais completo.
    pub const fn rp2350() -> Self {
        Self {
            secure_boot: true,
            trust_zone: true,
            hardware_rng: true,
            sha256_accelerator: true,
            debug_disable: true,
            otp_memory: true,
            unique_id: true,
            tamper_detection: false,
        }
    }

    /// Indica se ao menos um recurso de segurança está presente.
    pub fn has_any(&self) -> bool {
        self.secure_boot
            || self.trust_zone
            || self.hardware_rng
            || self.sha256_accelerator
            || self.debug_disable
            || self.otp_memory
            || self.unique_id
            || self.tamper_detection
    }
}

/// Fonte automática de user presence configurada no board.
///
/// Descreve como o board expõe o toque físico do usuário. O host
/// (`EmbeddedAuthenticator::new_with_board`) usa isso para injetar o sensor
/// correto no check de `up` do CTAP2, sem chamada manual a
/// `set_user_presence_button`. No target embarcado, o mesmo papel é cumprido
/// pelo método [`BoardTrait::button_pressed`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UserPresenceSource {
    /// Sem fonte automática — user presence é injetado manualmente (ou ausente).
    #[default]
    None,
    /// Botão BOOTSEL reaproveitado (linha CS da flash QSPI) — ex.: RP2350.
    ///
    /// Zero fiação extra: o BOOTSEL já vem soldado no board.
    Bootsel,
}

/// Descrição estática de um board: identidade, transportes e pinagem.
///
/// Todos os construtores são `const` para que perfis vivam em flash e sejam
/// validados em tempo de compilação.
#[derive(Clone, Copy, Debug)]
pub struct BoardDefinition {
    /// Nome do board, usado como `product_name` padrão.
    pub name: &'static str,
    /// AAGUID do modelo, deve ser único por produto.
    pub aaguid: [u8; 16],
    /// Bitmask de transportes suportados (ver `TRANSPORT_*`).
    pub transports: u8,
    /// Indica secure element ou flash cifrada disponível.
    pub has_secure_storage: bool,
    /// Indica acelerador criptográfico em hardware.
    pub has_crypto_accelerator: bool,
    /// Recursos de segurança do silício.
    pub security: SecurityFeatures,
    /// GPIO do sinal I2C SDA.
    pub i2c_sda_pin: u8,
    /// GPIO do sinal I2C SCL.
    pub i2c_scl_pin: u8,
    /// GPIO do sinal SPI MOSI.
    pub spi_mosi_pin: u8,
    /// GPIO do sinal SPI MISO.
    pub spi_miso_pin: u8,
    /// GPIO do clock SPI.
    pub spi_clk_pin: u8,
    /// GPIO do chip select.
    pub cs_pin: u8,
    /// GPIO de reset do periférico.
    pub reset_pin: u8,
    /// GPIO de interrupção.
    pub irq_pin: u8,
    /// GPIO do LED de status.
    pub led_pin: u8,
    /// GPIO do botão de user presence.
    pub button_pin: u8,
    /// Fonte automática de user presence (ex.: [`UserPresenceSource::Bootsel`]).
    pub presence_source: UserPresenceSource,
}

impl BoardDefinition {
    /// Cria uma definição mínima; os demais campos vêm dos builders `const`.
    pub const fn new(name: &'static str, aaguid: [u8; 16]) -> Self {
        Self {
            name,
            aaguid,
            transports: 0,
            has_secure_storage: false,
            has_crypto_accelerator: false,
            security: SecurityFeatures::none(),
            i2c_sda_pin: 0,
            i2c_scl_pin: 0,
            spi_mosi_pin: 0,
            spi_miso_pin: 0,
            spi_clk_pin: 0,
            cs_pin: 0,
            reset_pin: 0,
            irq_pin: 0,
            led_pin: 0,
            button_pin: 0,
            presence_source: UserPresenceSource::None,
        }
    }

    /// Define o GPIO do I2C SDA.
    pub const fn i2c_sda(mut self, pin: u8) -> Self {
        self.i2c_sda_pin = pin;
        self
    }
    /// Define o GPIO do I2C SCL.
    pub const fn i2c_scl(mut self, pin: u8) -> Self {
        self.i2c_scl_pin = pin;
        self
    }
    /// Define o GPIO do SPI MOSI.
    pub const fn spi_mosi(mut self, pin: u8) -> Self {
        self.spi_mosi_pin = pin;
        self
    }
    /// Define o GPIO do SPI MISO.
    pub const fn spi_miso(mut self, pin: u8) -> Self {
        self.spi_miso_pin = pin;
        self
    }
    /// Define o GPIO do clock SPI.
    pub const fn spi_clk(mut self, pin: u8) -> Self {
        self.spi_clk_pin = pin;
        self
    }
    /// Define o GPIO do chip select.
    pub const fn cs(mut self, pin: u8) -> Self {
        self.cs_pin = pin;
        self
    }
    /// Define o GPIO de reset.
    pub const fn reset(mut self, pin: u8) -> Self {
        self.reset_pin = pin;
        self
    }
    /// Define o GPIO de interrupção.
    pub const fn irq(mut self, pin: u8) -> Self {
        self.irq_pin = pin;
        self
    }
    /// Define o GPIO do LED de status.
    pub const fn led(mut self, pin: u8) -> Self {
        self.led_pin = pin;
        self
    }
    /// Define o GPIO do botão de user presence.
    pub const fn button(mut self, pin: u8) -> Self {
        self.button_pin = pin;
        self
    }
    /// Define a fonte automática de user presence do board.
    ///
    /// Ex.: [`UserPresenceSource::Bootsel`] no RP2350 (botão BOOTSEL sem GPIO).
    pub const fn presence_source(mut self, source: UserPresenceSource) -> Self {
        self.presence_source = source;
        self
    }
    /// Habilita o transporte USB-CCID.
    pub const fn usb_ccid(mut self) -> Self {
        self.transports |= TRANSPORT_USB_CCID;
        self
    }
    /// Habilita o transporte USB-HID.
    pub const fn usb_hid(mut self) -> Self {
        self.transports |= TRANSPORT_USB_HID;
        self
    }
    /// Habilita o transporte NFC.
    pub const fn nfc(mut self) -> Self {
        self.transports |= TRANSPORT_NFC;
        self
    }
    /// Habilita o transporte BLE GATT.
    pub const fn ble(mut self) -> Self {
        self.transports |= TRANSPORT_BLE;
        self
    }
    /// Declara disponibilidade de storage seguro.
    pub const fn secure_storage(mut self, enabled: bool) -> Self {
        self.has_secure_storage = enabled;
        self
    }
    /// Declara disponibilidade de acelerador criptográfico.
    pub const fn crypto_accelerator(mut self, enabled: bool) -> Self {
        self.has_crypto_accelerator = enabled;
        self
    }
    /// Substitui todo o conjunto de recursos de segurança.
    pub const fn security_features(mut self, features: SecurityFeatures) -> Self {
        self.security = features;
        self
    }
    /// Declara suporte a secure boot.
    pub const fn secure_boot(mut self, enabled: bool) -> Self {
        self.security.secure_boot = enabled;
        self
    }
    /// Declara suporte a TrustZone.
    pub const fn trust_zone(mut self, enabled: bool) -> Self {
        self.security.trust_zone = enabled;
        self
    }
    /// Declara RNG em hardware.
    pub const fn hardware_rng(mut self, enabled: bool) -> Self {
        self.security.hardware_rng = enabled;
        self
    }
    /// Declara acelerador SHA-256.
    pub const fn sha256_accelerator(mut self, enabled: bool) -> Self {
        self.security.sha256_accelerator = enabled;
        self
    }
    /// Declara possibilidade de desabilitar debug.
    pub const fn debug_disable(mut self, enabled: bool) -> Self {
        self.security.debug_disable = enabled;
        self
    }
    /// Declara memória OTP.
    pub const fn otp_memory(mut self, enabled: bool) -> Self {
        self.security.otp_memory = enabled;
        self
    }
    /// Declara identificador único em hardware.
    pub const fn unique_id(mut self, enabled: bool) -> Self {
        self.security.unique_id = enabled;
        self
    }
    /// Declara detecção de violação física.
    pub const fn tamper_detection(mut self, enabled: bool) -> Self {
        self.security.tamper_detection = enabled;
        self
    }

    /// Verifica se o board expõe o(s) transporte(s) da máscara informada.
    pub const fn has_transport(&self, mask: u8) -> bool {
        self.transports & mask != 0
    }
}

/// Instância de runtime de um board, criada a partir de sua definição.
pub struct BoardHAL {
    config: BoardDefinition,
}

impl BoardHAL {
    /// Inicializa o HAL para a definição informada.
    pub fn new(config: BoardDefinition) -> Self {
        info!("Board HAL initialized for {}", config.name);
        Self { config }
    }

    /// Definição estática que originou este HAL.
    pub fn get_config(&self) -> &BoardDefinition {
        &self.config
    }
}

/// Wrapper sobre um barramento `embedded-hal` I2C com acesso a registradores.
pub struct I2cBus<I2C> {
    inner: I2C,
}

impl<I2C, E> I2cBus<I2C>
where
    I2C: I2c<Error = E>,
{
    /// Assume a posse do barramento I2C.
    pub fn new(inner: I2C) -> Self {
        debug!("I2C bus initialized");
        Self { inner }
    }

    /// Lê um registrador de 8 bits do dispositivo em `addr`.
    pub fn read_register(&mut self, addr: u8, reg: u8) -> Result<[u8; 1], E> {
        let mut buf = [0u8; 1];
        self.inner.write(addr, &[reg])?;
        self.inner.read(addr, &mut buf)?;
        Ok(buf)
    }

    /// Escreve um registrador de 8 bits do dispositivo em `addr`.
    pub fn write_register(&mut self, addr: u8, reg: u8, value: u8) -> Result<(), E> {
        self.inner.write(addr, &[reg, value])?;
        Ok(())
    }
}

/// Pino GPIO bidirecional (entrada e saída), usado para LED e botão.
pub struct GpioPin<P> {
    pin: P,
}

impl<P, E> GpioPin<P>
where
    P: InputPin<Error = E> + OutputPin<Error = E>,
{
    /// Assume a posse do pino.
    pub fn new(pin: P) -> Self {
        debug!("GPIO pin initialized");
        Self { pin }
    }

    /// Coloca o pino em nível alto.
    pub fn set_high(&mut self) -> Result<(), P::Error> {
        self.pin.set_high()
    }

    /// Coloca o pino em nível baixo.
    pub fn set_low(&mut self) -> Result<(), P::Error> {
        self.pin.set_low()
    }

    /// Lê se o pino está em nível alto.
    pub fn is_high(&mut self) -> Result<bool, P::Error> {
        self.pin.is_high()
    }

    /// Lê se o pino está em nível baixo.
    pub fn is_low(&mut self) -> Result<bool, P::Error> {
        self.pin.is_low()
    }

    /// Inverte o nível atual do pino.
    pub fn toggle(&mut self) -> Result<(), P::Error> {
        if self.pin.is_low()? {
            self.pin.set_high()
        } else {
            self.pin.set_low()
        }
    }
}

/// Contrato que um board concreto implementa para expor seus periféricos.
///
/// Os métodos de LED e delay têm implementação padrão vazia para que boards
/// sem esses recursos possam implementar apenas o essencial.
pub trait BoardTrait {
    /// Tipo do barramento I2C do board.
    type I2C;
    /// Tipo do barramento SPI do board.
    type SPI;
    /// Tipo do controlador GPIO do board.
    type GPIO;

    /// Acesso mutável ao barramento I2C.
    fn i2c(&mut self) -> &mut Self::I2C;
    /// Acesso mutável ao barramento SPI.
    fn spi(&mut self) -> &mut Self::SPI;
    /// Acesso mutável ao controlador GPIO.
    fn gpio(&mut self) -> &mut Self::GPIO;

    /// Reinicia o hardware do board.
    fn reset(&mut self) {
        debug!("Board reset triggered");
    }

    /// Acende o LED de status.
    fn led_on(&mut self) {
        debug!("LED turned on");
    }

    /// Apaga o LED de status.
    fn led_off(&mut self) {
        debug!("LED turned off");
    }

    /// Pisca o LED `count` vezes — sinaliza pedido de user presence.
    fn led_blink(&mut self, count: u8) {
        for _ in 0..count {
            self.led_on();
            self.delay_ms(100);
            self.led_off();
            self.delay_ms(100);
        }
    }

    /// Aguarda `ms` milissegundos. Implementação padrão é no-op.
    fn delay_ms(&mut self, ms: u32) {
        let _ = ms;
    }

    /// Lê o botão de user presence. Padrão `false` (não pressionado).
    ///
    /// Boards com botão dedicado (ou que reaproveitam o BOOTSEL) devem
    /// sobrescrever para consultar o pino ou [`crate::bootsel::BootselButton`].
    fn button_pressed(&mut self) -> bool {
        false
    }
}
