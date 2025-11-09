#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <hash.h>

struct sup_page_table_entry {
    uint32_t* vaddr;
    uint64_t access_time;
    bool dirty;
    bool accessed;
    struct hash_elem hash_elem;
};

void sup_page_table_init(struct hash*);
void sup_page_insert(struct hash*,struct sup_page_table_entry*);

#endif /* vm/page.h */