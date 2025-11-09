#include "vm/frame.h"
#include "threads/malloc.h"
void
frame_table_init(void){
    list_init(&frame_table);
}

void * 
frame_table_insert(void* vaddr, enum palloc_flags flags){
    struct frame_table_entry* frame_entry;
    frame_entry = (struct frame_table_entry*) malloc(sizeof(struct frame_table_entry));

    frame_entry->frame = (uint32_t*) palloc_get_page(flags);
    frame_entry->owner = thread_current();
    frame_entry->page = NULL; //temp
    
    list_push_back(&frame_table,&frame_entry->list_elem);

    return (void *) frame_entry->frame;
}