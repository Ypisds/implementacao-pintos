#include "vm/swap.h"
#include "devices/block.h"

static struct block* global_swap_block;
void read_from_block(uint8_t* frame, int index);
void write_from_block(uint8_t* frame, int index);


void 
swap_init(){
    global_swap_block = block_get_role(BLOCK_SWAP);
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