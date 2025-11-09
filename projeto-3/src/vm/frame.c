#include "vm/frame.h"
#include "threads/malloc.h"
#include "devices/timer.h"
void
frame_table_init(void){
    list_init(&frame_table);
}

void * 
frame_table_insert(void* vaddr, enum palloc_flags flags){
    struct frame_table_entry* frame_entry;
    struct sup_page_table_entry* sup_page_table_entry;
    frame_entry = (struct frame_table_entry*) malloc(sizeof(struct frame_table_entry));
    sup_page_table_entry = (struct sup_page_table_entry*) malloc(sizeof(struct sup_page_table_entry));

    sup_page_table_entry->vaddr = vaddr;
    sup_page_table_entry->access_time = timer_ticks();
    sup_page_table_entry->dirty = false;
    sup_page_table_entry->accessed = false;

    sup_page_insert(&thread_current()->sup_page_table, sup_page_table_entry);

    frame_entry->frame = (uint32_t*) palloc_get_page(flags);
    frame_entry->owner = thread_current();
    frame_entry->page = sup_page_table_entry; 
    
    list_push_back(&frame_table,&frame_entry->list_elem);

    return (void *) frame_entry->frame;
}