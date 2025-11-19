#include "vm/frame.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "lib/kernel/list.h"
#include "userprog/pagedir.h"


static bool access_frame_comparison (const struct list_elem *a, const struct list_elem *b,void *aux);
struct lock frame_lock;
static struct list_elem* frame_elem;
struct frame_table_entry *create_frame_table_entry(struct sup_page_table_entry *sup_page_table_entry, void* frame_addr);
void install_page_in_memory(struct sup_page_table_entry *spt_entry, void *kpage);

void
frame_table_init(void){
    list_init(&frame_table);
    lock_init(&frame_lock);
    frame_elem = NULL;
}

void  
frame_table_insert(struct sup_page_table_entry *sup_page_table_entry, void* frame_addr){
    
    struct frame_table_entry* frame_entry = create_frame_table_entry(sup_page_table_entry, frame_addr);
    
    list_push_back(&frame_table,&frame_entry->list_elem);
    
    if(frame_elem == NULL) frame_elem=list_begin(&frame_table);

}

struct frame_table_entry *create_frame_table_entry(struct sup_page_table_entry *sup_page_table_entry, void* frame_addr) {
    struct frame_table_entry* frame_entry;
    frame_entry = (struct frame_table_entry*) malloc(sizeof(struct frame_table_entry));

    frame_entry->frame = (uint32_t*) frame_addr;
    frame_entry->owner = thread_current();
    frame_entry->page = sup_page_table_entry; 
    frame_entry->pinned = false;
    return frame_entry;
}

struct frame_table_entry* frame_get_entry_by_kpage(void *kpage){
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

// bool access_frame_comparison (const struct list_elem *a, const struct list_elem *b,
//                       void *aux) {
//   struct frame_table_entry *left_frame = list_entry(a, struct frame_table_entry, list_elem);
//   struct frame_table_entry *right_frame = list_entry(b, struct frame_table_entry, list_elem);
  
//   if(left_frame -> access_time < right_frame->access_time) {
//     return true;
//   } else {
//     return false;
//   }

// }

void frame_pin(void *kpage) {
  lock_acquire(&frame_lock);
  struct frame_table_entry* fte = frame_get_entry_by_kpage(kpage);
  fte->pinned=true;
  lock_release(&frame_lock);
}
void frame_unpin(void *kpage){
  lock_acquire(&frame_lock);
  struct frame_table_entry* fte = frame_get_entry_by_kpage(kpage);
  fte->pinned=false;
  lock_release(&frame_lock);
}

void *eviction(){
  lock_acquire(&frame_lock);

  while(true) {
    if(list_empty(&frame_table)) {
      lock_release(&frame_lock);
      return NULL;
    }

    if(frame_elem == NULL || frame_elem == list_end(&frame_table)) frame_elem = list_begin(&frame_table);
    struct frame_table_entry* fte = list_entry(frame_elem, struct frame_table_entry, list_elem);
    
    frame_elem = list_next(frame_elem);

    if(fte->pinned) continue;

    struct thread* curr = fte->owner;
    void *upage = fte->page->vaddr;
    
    
    if(pagedir_is_accessed(curr->pagedir, upage)){
      pagedir_set_accessed(curr->pagedir, upage, false);
    }
    else {
      if(fte->page->file == NULL || pagedir_is_dirty(curr->pagedir, upage)){
        size_t index = swap_out(fte->frame);
        fte->page->index = index;
        fte->page->in_memory=false;
        fte->page->swap=true; 
      }
      else{
        fte->page->in_memory=false;
      }
      void *kpage = fte->frame;
      pagedir_clear_page(curr->pagedir, upage);
      list_remove(&fte->list_elem);
      free(fte); 
      lock_release(&frame_lock);
      
      
      return kpage;
    }
    
  }
}

void install_page_in_memory(struct sup_page_table_entry *spt_entry, void *kpage){
  struct thread* curr = thread_current();
  spt_entry->in_memory=true;
  lock_acquire(&frame_lock);
  frame_table_insert(spt_entry, kpage);
  lock_release(&frame_lock);
}