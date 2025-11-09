#include "page.h"

static unsigned sup_page_hash(const struct hash_elem *elem, void *aux);
static bool sup_page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);

void sup_page_table_init(struct hash* sup_page_table){
    hash_init(sup_page_table,sup_page_hash,sup_page_less,NULL);
}

void sup_page_insert(struct hash* sup_page_table,struct sup_page_table_entry* page){
    hash_insert(sup_page_table,&page->hash_elem);
}

static unsigned sup_page_hash(const struct hash_elem *elem, void *aux){
    const struct sup_page_table_entry *p = hash_entry (elem, struct sup_page_table_entry, hash_elem);
    return hash_bytes (&p->vaddr, sizeof p->vaddr);
}

static bool sup_page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux){
    const struct sup_page_table_entry *left_page = hash_entry (a, struct sup_page_table_entry, hash_elem);
    const struct sup_page_table_entry *right_page = hash_entry (b, struct sup_page_table_entry, hash_elem);

    return left_page->vaddr < right_page->vaddr; 
}