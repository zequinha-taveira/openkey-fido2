MEMORY {
    /*
     * nRF52840: 1 MiB de flash + 256 KiB de RAM.
     * Sem softdevice: o vetor de interrupções fica em 0x00000000.
     */
    FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
    RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
