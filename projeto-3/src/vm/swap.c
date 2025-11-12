#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "lib/kernel/list.h"
#include <stdio.h>

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct block* global_swap_block;
static struct bitmap* swap_bitmap;
struct lock swap_lock;

void read_from_block(uint8_t* frame, block_sector_t start_sector);
void write_from_block(uint8_t* frame, block_sector_t start_sector);

void 
swap_init(void) {
    global_swap_block = block_get_role(BLOCK_SWAP);
    lock_init(&swap_lock);

    size_t total_sectors = block_size(global_swap_block);
    size_t total_slots = total_sectors / SECTORS_PER_PAGE;
    /* opcional: verificar divisibilidade */
    if (total_sectors % SECTORS_PER_PAGE != 0)
        PANIC("Swap block size not multiple of page sectors");

    swap_bitmap = bitmap_create(total_slots);
    if (!swap_bitmap)
        PANIC("Failed to create swap bitmap");
}

void
read_from_block(uint8_t* frame, block_sector_t start_sector) {
    for (size_t i = 0; i < SECTORS_PER_PAGE; ++i) {
        block_read(global_swap_block, start_sector + i,
                   frame + (i * BLOCK_SECTOR_SIZE));
    }
}

void
write_from_block(uint8_t* frame, block_sector_t start_sector) {
    for (size_t i = 0; i < SECTORS_PER_PAGE; ++i) {
        block_write(global_swap_block, start_sector + i,
                    frame + (i * BLOCK_SECTOR_SIZE));
    }
}

size_t
swap_out(void *kpage) {
    lock_acquire(&swap_lock);

    /* procurar 1 slot livre (um bit) */
    size_t slot = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    if (slot == BITMAP_ERROR) {
        lock_release(&swap_lock);
        PANIC("ESTOUROU O SWAP");
    }

    block_sector_t first_sector = (block_sector_t)(slot * SECTORS_PER_PAGE);
    write_from_block((uint8_t*)kpage, first_sector);

    lock_release(&swap_lock);
    return slot; /* retornamos slot (não setor) */
}

void
reclamation(void *kpage, size_t slot) {
    block_sector_t first_sector = (block_sector_t)(slot * SECTORS_PER_PAGE);
    lock_acquire(&swap_lock);

    read_from_block((uint8_t*)kpage, first_sector);

    /* marcar o slot como livre */
    bitmap_set(swap_bitmap, slot, false);

    lock_release(&swap_lock);
}
