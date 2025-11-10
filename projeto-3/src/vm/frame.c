#include "vm/frame.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "threads/synch.h"


static bool access_frame_comparison (const struct list_elem *a, const struct list_elem *b,void *aux);
struct lock frame_lock;

void
frame_table_init(void){
    list_init(&frame_table);
    lock_init(&frame_lock);
}

void  
frame_table_insert(void* vaddr, void* frame_addr){
    struct frame_table_entry* frame_entry;
    struct sup_page_table_entry* sup_page_table_entry;
    frame_entry = (struct frame_table_entry*) malloc(sizeof(struct frame_table_entry));
    sup_page_table_entry = (struct sup_page_table_entry*) malloc(sizeof(struct sup_page_table_entry));

    sup_page_table_entry->vaddr = vaddr;
    sup_page_table_entry->dirty = false;
    sup_page_table_entry->accessed = false;

    sup_page_insert(&thread_current()->sup_page_table, sup_page_table_entry);

    frame_entry->frame = (uint32_t*) frame_addr;
    frame_entry->owner = thread_current();
    frame_entry->page = sup_page_table_entry; 
    frame_entry->access_time = timer_ticks();
    
    list_insert_ordered(&frame_table,&frame_entry->list_elem,access_frame_comparison,NULL);

    return (void *) frame_entry->frame;
}

bool access_frame_comparison (const struct list_elem *a, const struct list_elem *b,
                      void *aux) {
  struct frame_table_entry *left_frame = list_entry(a, struct frame_table_entry, list_elem);
  struct frame_table_entry *right_frame = list_entry(b, struct frame_table_entry, list_elem);
  
  if(left_frame -> access_time < right_frame->access_time) {
    return true;
  } else {
    return false;
  }

}