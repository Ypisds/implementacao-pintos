#include "page.h"
#include "threads/vaddr.h"

static unsigned sup_page_hash(const struct hash_elem *elem, void *aux);
static bool sup_page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);
struct sup_page_table_entry* create_default_grow_stack_sup_entry(void * upage);

void sup_page_table_init(struct hash* sup_page_table){
    hash_init(sup_page_table,sup_page_hash,sup_page_less,NULL);
}

void sup_page_insert(struct hash* sup_page_table,struct sup_page_table_entry* page){
    hash_insert(sup_page_table,&page->hash_elem);
}

struct sup_page_table_entry* sup_page_get(struct hash *h, void *vaddr){
    struct sup_page_table_entry sup_temp;
    memset(&sup_temp, 0, sizeof sup_temp);
    sup_temp.vaddr = vaddr; 

    struct hash_elem *e = hash_find(h, &sup_temp.hash_elem);
    if (e != NULL)
        return hash_entry(e, struct sup_page_table_entry, hash_elem);
    return NULL;
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

struct sup_page_table_entry* create_default_grow_stack_sup_entry(void * upage){
    struct sup_page_table_entry *spt_entry = (struct sup_page_table_entry *)malloc(sizeof(struct sup_page_table_entry));
    spt_entry->vaddr = upage;
    spt_entry->writable = true;    
    spt_entry->in_memory = false;  
    spt_entry->swap = false;
    spt_entry->file = NULL;
    spt_entry->offset = 0;
    spt_entry->read_bytes = 0;
    spt_entry->zero_bytes = PGSIZE;
    spt_entry->index = 0;
    return spt_entry;
}