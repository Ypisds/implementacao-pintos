#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "lib/kernel/list.h"
#include <stdio.h>

#define SECTORS_PER_PAGE PGSIZE/BLOCK_SECTOR_SIZE

static struct block* global_swap_block;
void read_from_block(uint8_t* frame, int index);
void write_from_block(uint8_t* frame, int index);

static struct bitmap* swap_bitmap;
struct lock swap_lock;


void 
swap_init(){
    global_swap_block = block_get_role(BLOCK_SWAP);
    lock_init(&swap_lock);
    size_t total_size = block_size(global_swap_block);
    swap_bitmap = bitmap_create(block_size (global_swap_block));

}


void
read_from_block(uint8_t* frame, int index){

//the frame is the frame I want to read into / write from
//the index is the starting index of the block that is free
for(int i = 0; i < 8; ++i)
{
//each read/write will rea/write 512 bytes, therefore we need to read/write 8 times, each at 512 increments of the frame
block_read(global_swap_block, index + i, frame + (i * BLOCK_SECTOR_SIZE));
}

}
void
write_from_block(uint8_t* frame, int index){

//the frame is the frame I want to read into / write from
//the index is the starting index of the block that is free
for(int i = 0; i < 8; ++i)
{
//each read/write will rea/write 512 bytes, therefore we need to read/write 8 times, each at 512 increments of the frame
block_write(global_swap_block, index + i, frame + (i * BLOCK_SECTOR_SIZE));
}

}

static uint32_t page_checksum(void *kpage) {
    uint8_t *b = (uint8_t *) kpage;
    uint32_t s = 0;
    for (size_t i = 0; i < PGSIZE; ++i) s = s + b[i];
    return s;
}

size_t swap_out(void *kpage){
    lock_acquire(&swap_lock);
    size_t index = bitmap_scan_and_flip(swap_bitmap, 0, 8, false);
    if(index == BITMAP_ERROR) PANIC("ESTOUROU O SWAP");
    
    block_sector_t sector = index;
    uint32_t cs = page_checksum(kpage);
    printf("[SWAP_OUT] kpage=%p slot_sector_start=%u (sector) slot_index=%zu checksum=%u\n",
           kpage, (unsigned)sector, index, cs);

    write_from_block(kpage, sector);
    lock_release(&swap_lock);
    
    return index;
}

void reclamation(void *kpage, size_t index){
    block_sector_t sector = index;
    lock_acquire(&swap_lock);
    printf("[SWAP_IN] about to read into kpage=%p sector_start=%u (index=%zu)\n",
           kpage, (unsigned)sector, index);
    read_from_block(kpage, sector);

    uint32_t cs = page_checksum(kpage);
    printf("[SWAP_IN] kpage=%p sector_start=%u checksum=%u\n", kpage, (unsigned)sector, cs);
    
    for(int i = 0; i < 8; i++) {
        bitmap_set(swap_bitmap, index+i, false);
    }
    
    lock_release(&swap_lock);
}