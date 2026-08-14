MEMORY {
    /*
     * O RP2350 tem flash externo (via QSPI) mapeado em XIP.
     *
     * 2 MiB é um padrão seguro; um Pico 2 tem 4 MiB.
     */
    FLASH : ORIGIN = 0x10000000, LENGTH = 2048K
    /*
     * RAM consiste em 8 bancos (SRAM0-SRAM7) com mapeamento em stripe,
     * o que distribui a carga uniformemente entre os bancos.
     */
    RAM : ORIGIN = 0x20000000, LENGTH = 512K
    /*
     * Os bancos 8 e 9 usam mapeamento direto, úteis para áreas dedicadas
     * (ex.: stacks separadas para core0 e core1).
     */
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

SECTIONS {
    /* ### Boot ROM info
     *
     * Vai depois de .vector_table, para ficar nos primeiros 4K de flash,
     * onde a Boot ROM (e o picotool) podem encontrá-lo.
     */
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH

} INSERT AFTER .vector_table;

/* move .text para iniciar /depois/ do boot info */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    /* ### Picotool 'Binary Info' Entries
     *
     * O picotool procura neste bloco (há ponteiros para ele no header)
     * por informações relevantes sobre o binário.
     */
    .bi_entries : ALIGN(4)
    {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    /* ### Boot ROM extra info
     *
     * Vai depois de tudo, podendo conter uma assinatura.
     */
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
        __flash_binary_end = .;
    } > FLASH

} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);
