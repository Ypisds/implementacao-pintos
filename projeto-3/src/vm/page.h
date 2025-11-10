#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <inttypes.h>
#include <hash.h>

struct sup_page_table_entry {
    uint32_t* vaddr;
    bool dirty;
    bool accessed;
    struct hash_elem hash_elem;
};

void sup_page_table_init(struct hash*);
void sup_page_insert(struct hash*,struct sup_page_table_entry*);

#endif /* vm/page.h */