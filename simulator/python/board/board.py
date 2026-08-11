"""Board virtual do simulador: agrega os periféricos emulados.

Espelha `BoardTrait` de `firmware/board-generic` (`i2c`/`spi`/`gpio`/`reset`/
`led_*`/`delay_ms`) e a `BoardDefinition` (transports, pinos, secure storage,
crypto accelerator). O storage emulado guarda credenciais e o contador de
signatures em memória, no formato usado pelo simulador Rust.
"""

from pathlib import Path

from . import profiles


class VirtualBoard:
    def __init__(self, profile=None, gpio=None, i2c=None, spi=None, ccid=None):
        self.config = profile if profile is not None else profiles.GENERIC
        self.gpio = gpio
        self.i2c = i2c
        self.spi = spi
        self.ccid = ccid if ccid is not None else CcidBoard()
        self.reset_count = 0
        self.led_state = False
        self.delay_total_ms = 0
        self.credentials = {}
        self.sign_counters = {}

    def reset(self):
        self.reset_count += 1
        self.led_state = False

    def led_on(self):
        self.led_state = True
        if self.config.led_pin is not None and self.gpio is not None:
            self.gpio.set_high(self.config.led_pin)

    def led_off(self):
        self.led_state = False
        if self.config.led_pin is not None and self.gpio is not None:
            self.gpio.set_low(self.config.led_pin)

    def led_blink(self, count=1):
        for _ in range(count):
            self.led_on()
            self.delay_ms(100)
            self.led_off()
            self.delay_ms(100)

    def delay_ms(self, ms):
        self.delay_total_ms += ms

    def has_transport(self, mask):
        return self.config.transports & mask != 0

    def store_credential(self, credential_id, credential):
        self.credentials[credential_id] = credential

    def get_credential(self, credential_id):
        return self.credentials.get(credential_id)

    def all_credentials(self):
        return list(self.credentials.values())

    def bump_sign_counter(self, credential_id):
        current = self.sign_counters.get(credential_id, 0)
        self.sign_counters[credential_id] = current + 1
        return self.sign_counters[credential_id]


class CcidBoard:
    """Transport CCID emulado em nível de mensagem (APDU)."""

    def __init__(self):
        self.exchanges = []

    def send(self, payload):
        response = b"ok"
        self.exchanges.append((payload, response))
        return response
