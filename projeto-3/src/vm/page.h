#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <inttypes.h>
#include <hash.h>
#include "filesys/file.h"

struct sup_page_table_entry {
    uint32_t* vaddr;
    struct file *file;
    off_t offset;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    size_t index;
    bool writable;
    bool dirty;
    bool accessed;
    bool swap;
    bool in_memory;
    struct hash_elem hash_elem;
};

void sup_page_table_init(struct hash*);
void sup_page_insert(struct hash*,struct sup_page_table_entry*);
struct sup_page_table_entry* sup_page_get(struct hash *h, void *vaddr);

#endif /* vm/page.h */