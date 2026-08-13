//! Detecção de user presence reaproveitando o botão BOOTSEL do RP2350.
//!
//! No RP2350 (Raspberry Pi Pico 2) o botão BOOTSEL fica ligado à linha de
//! chip-select (CS) da flash QSPI — **não é um GPIO comum**. Para lê-lo em
//! runtime é preciso desligar o XIP (execute-in-place), reconfigurar o pino
//! como entrada SIO, amostrar o nível e restaurar a configuração.
//!
//! A vantagem é **zero fiação extra**: o botão já vem soldado no board, então
//! ele serve como sensor de user presence sem custo adicional de hardware.
//!
//! Como o target embarcado não roda neste repositório (std/host), os passos de
//! hardware ficam documentados com placeholders, seguindo o mesmo padrão de
//! `Rp2350UsbPeriph` em `transport::embedded::rp2350`.

/// Contrato de um sensor de user presence (toque físico).
pub trait UserPresenceButton: Send + Sync {
    /// Retorna `true` se o botão está pressionado neste instante.
    fn is_pressed(&mut self) -> bool;
}

/// Placeholder do periférico SSI/QSPI do RP2350.
///
/// Numa implementação real, seria `rp2350_hal::ssi::Ssi` (ou acesso direto via
/// `rp2350-pac`). O campo `cs_level` simula o nível lógico da linha CS: `true`
/// = nível alto (botão solto, estado idle) e `false` = nível baixo (botão
/// pressionado).
#[derive(Debug)]
pub struct Rp2350Qspi {
    cs_level: bool,
}

impl Rp2350Qspi {
    /// Cria o placeholder com a linha CS em nível alto (botão solto).
    pub fn new() -> Self {
        Self { cs_level: true }
    }

    /// Simula o nível lógico da linha CS — em hardware, lido de `SIO_GPIO_IN`.
    pub fn set_cs_level(&mut self, high: bool) {
        self.cs_level = high;
    }

    /// Desliga o execute-in-place da flash.
    fn disable_xip(&mut self) {
        // Real: SSI_SSIENR.SSI_EN = 0 e aguardar o SSI drenar.
    }

    /// Reconfigura o pino QSPI_SS_N como entrada SIO com pull-up.
    fn cs_as_gpio_input(&mut self) {
        // Real: IO_BANK0.GPIOx_CTRL.FUNCSEL = SIO; OE = input; pad com pull-up.
    }

    /// Amostra o nível lógico da linha CS.
    fn read_cs(&self) -> bool {
        self.cs_level
    }

    /// Restaura a função QSPI do pino e religa o XIP.
    fn restore_xip(&mut self) {
        // Real: devolver FUNCSEL à função QSPI e SSI_EN = 1.
    }
}

impl Default for Rp2350Qspi {
    fn default() -> Self {
        Self::new()
    }
}

/// Botão BOOTSEL do RP2350 usado como sensor de user presence.
///
/// O BOOTSEL é ativo-baixo: quando pressionado, puxa a linha CS para GND.
#[derive(Debug)]
pub struct BootselButton {
    qspi: Rp2350Qspi,
}

impl BootselButton {
    /// Cria o sensor sobre o periférico QSPI informado.
    pub fn new(qspi: Rp2350Qspi) -> Self {
        Self { qspi }
    }

    /// Acesso mutável ao QSPI — permite simular press/release em testes.
    pub fn qspi_mut(&mut self) -> &mut Rp2350Qspi {
        &mut self.qspi
    }
}

impl UserPresenceButton for BootselButton {
    fn is_pressed(&mut self) -> bool {
        // Sequência crítica: desligar XIP, amostrar o CS e restaurar.
        self.qspi.disable_xip();
        self.qspi.cs_as_gpio_input();
        let pressed = !self.qspi.read_cs(); // ativo-baixo: CS baixo = pressionado
        self.qspi.restore_xip();
        pressed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootsel_not_pressed_by_default() {
        let mut button = BootselButton::new(Rp2350Qspi::new());
        assert!(!button.is_pressed());
    }

    #[test]
    fn test_bootsel_press_and_release() {
        let mut button = BootselButton::new(Rp2350Qspi::new());

        assert!(!button.is_pressed()); // idle: solto
        button.qspi_mut().set_cs_level(false); // pressiona (CS -> GND)
        assert!(button.is_pressed());
        button.qspi_mut().set_cs_level(true); // solta
        assert!(!button.is_pressed());
    }

    #[test]
    fn test_user_presence_button_is_object_safe() {
        let mut button = BootselButton::new(Rp2350Qspi::new());
        let presence: &mut dyn UserPresenceButton = &mut button;
        assert!(!presence.is_pressed());
    }
}
