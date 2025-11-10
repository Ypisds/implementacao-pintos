#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <inttypes.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "vm/page.h"

static struct list frame_table;

struct frame_table_entry {
    uint32_t* frame;
    struct thread* owner;
    struct sup_page_table_entry* page;
    uint64_t access_time;
    struct list_elem list_elem;
};

void frame_table_init(void);
void frame_table_insert(void*,void*);
#endif /* vm/frame.h */