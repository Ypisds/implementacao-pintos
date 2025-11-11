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
frame_table_insert(struct sup_page_table_entry *sup_page_table_entry, void* frame_addr){
    struct frame_table_entry* frame_entry;
    frame_entry = (struct frame_table_entry*) malloc(sizeof(struct frame_table_entry));

    frame_entry->frame = (uint32_t*) frame_addr;
    frame_entry->owner = thread_current();
    frame_entry->page = sup_page_table_entry; 
    frame_entry->access_time = timer_ticks();
    frame_entry->pinned = false;
    
    list_insert_ordered(&frame_table,&frame_entry->list_elem,access_frame_comparison,NULL);

    return (void *) frame_entry->frame;
}

struct frame_table_entry* frame_get_entry(void *kpage){
  

  if(list_empty(&frame_table)){
    
    return NULL;
  } 
  struct list_elem* e;
  struct frame_table_entry * fte;
  for(e=list_begin(&frame_table); e != list_end(&frame_table); e=list_next(e)){
    fte = list_entry(e, struct frame_table_entry, list_elem);
    if(fte->frame==kpage) {
      
      return fte;
    }
  }
  
  return NULL;
}

void *get_kpage_from_upage(void *upage){
  

  if(list_empty(&frame_table)){
    
    return NULL;
  }
   struct list_elem* e;
  struct frame_table_entry * fte;
  for(e=list_begin(&frame_table); e != list_end(&frame_table); e=list_next(e)){
    fte = list_entry(e, struct frame_table_entry, list_elem);
    if(fte->page->vaddr==upage) {
      
      return fte->frame;
    }
  }
  
  return NULL;
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

void frame_pin(void *kpage) {
  lock_acquire(&frame_lock);
  struct frame_table_entry* fte = frame_get_entry(kpage);
  fte->pinned=true;
  lock_release(&frame_lock);
}
void frame_unpin(void *kpage){
  lock_acquire(&frame_lock);
  struct frame_table_entry* fte = frame_get_entry(kpage);
  fte->pinned=false;
  lock_release(&frame_lock);
}