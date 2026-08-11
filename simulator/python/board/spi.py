"""Emulação de barramento SPI do virtual board.

Espelha o SPI mestre de `board-generic` (MOSI/MISO/CLK/CS). A resposta MISO
é configurável por `miso_transform`; por padrão ecoa os bytes MOSI (loopback).
"""


class SPIBus:
    def __init__(self, mosi_pin=2, miso_pin=3, clk_pin=4, cs_pin=5, gpio=None, miso_transform=None):
        self.mosi_pin = mosi_pin
        self.miso_pin = miso_pin
        self.clk_pin = clk_pin
        self.cs_pin = cs_pin
        self.gpio = gpio
        self.miso_transform = miso_transform or (lambda data: data)
        self.cs_asserted = False
        self.bytes_transferred = 0
        self.last_transfer = b""

    def select(self):
        self.cs_asserted = True

    def deassert(self):
        self.cs_asserted = False

    def transfer(self, data):
        if not self.cs_asserted:
            self.cs_asserted = True
        payload = bytes(data)
        response = bytes(self.miso_transform(payload))
        if len(response) != len(payload):
            raise ValueError("miso_transform deve preservar o comprimento")
        self.bytes_transferred += len(payload)
        self.last_transfer = response
        return response
