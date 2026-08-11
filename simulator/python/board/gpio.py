"""Emulação de GPIO do virtual board.

Espelha `GpioPin` de `board-generic` (set_high/set_low/toggle/is_high/is_low)
com notificação de bordas simulada (IRQ). Um `GpioController` indexa os pinos
por número de pino do board.
"""


class GpioPin:
    def __init__(self, number, initial=0):
        self.number = number
        self.value = 1 if initial else 0
        self.listeners = []

    def set_high(self):
        self._write(1)

    def set_low(self):
        self._write(0)

    def toggle(self):
        self._write(0 if self.value else 1)

    def write(self, value):
        self._write(1 if value else 0)

    def read(self):
        return self.value

    def is_high(self):
        return self.value == 1

    def is_low(self):
        return self.value == 0

    def add_listener(self, callback):
        self.listeners.append(callback)

    def _write(self, value):
        if value != self.value:
            self.value = value
            for callback in self.listeners:
                callback(self.number, value)


class GpioController:
    def __init__(self):
        self._pins = {}

    def pin(self, number):
        if number not in self._pins:
            self._pins[number] = GpioPin(number)
        return self._pins[number]

    def set_high(self, number):
        self.pin(number).set_high()

    def set_low(self, number):
        self.pin(number).set_low()

    def is_high(self, number):
        return self.pin(number).is_high()

    def is_low(self, number):
        return self.pin(number).is_low()

    def toggle(self, number):
        self.pin(number).toggle()

    def pulse(self, number, ticks=1):
        for _ in range(ticks):
            self.pin(number).toggle()
