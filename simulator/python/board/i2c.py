"""Emulação de barramento I2C do virtual board.

Espelha `I2cBus` de `board-generic`: read_register/write_register e
transações write/read sobre dispositivos com mapa de registradores.
Registra a sequência de transações para inspeção nos testes.
"""


class I2CDevice:
    def __init__(self, address, registers=None):
        self.address = address
        self.registers = dict(registers or {})
        self.last_register = 0

    def write_register(self, reg, value):
        self.registers[reg] = value
        self.last_register = reg

    def read_register(self, reg):
        self.last_register = reg
        return self.registers.get(reg, 0)


class I2CBus:
    def __init__(self, sda_pin=0, scl_pin=1, gpio=None):
        self.sda_pin = sda_pin
        self.scl_pin = scl_pin
        self.gpio = gpio
        self.devices = {}
        self.transactions = []

    def add_device(self, device):
        self.devices[device.address] = device

    def device(self, address):
        if address not in self.devices:
            raise KeyError(f"nenhum dispositivo I2C no endereço 0x{address:02x}")
        return self.devices[address]

    def write_register(self, addr, reg, value):
        self._record("write_register", addr, [reg, value])
        self.device(addr).write_register(reg, value)

    def read_register(self, addr, reg):
        self._record("read_register", addr, [reg])
        return self.device(addr).read_register(reg)

    def write(self, addr, data):
        self._record("write", addr, list(data))
        if not data:
            return
        reg = data[0]
        for value in data[1:]:
            self.device(addr).write_register(reg, value)

    def read(self, addr, length):
        self._record("read", addr, [length])
        device = self.device(addr)
        return [device.read_register(device.last_register) for _ in range(length)]

    def _record(self, kind, addr, payload):
        self.transactions.append((kind, addr, tuple(payload)))
