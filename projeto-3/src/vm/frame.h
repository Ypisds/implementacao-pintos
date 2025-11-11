#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <inttypes.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "vm/page.h"
#include "threads/synch.h"

static struct list frame_table;
extern struct lock frame_lock;

struct frame_table_entry {
    uint32_t* frame;
    struct thread* owner;
    struct sup_page_table_entry* page;
    bool pinned;
    uint64_t access_time;
    struct list_elem list_elem;
};

void frame_table_init(void);
void frame_table_insert(struct sup_page_table_entry *,void*);
void frame_pin(void *);
void frame_unpin(void *);
void *get_kpage_from_upage(void *);

#endif /* vm/frame.h */