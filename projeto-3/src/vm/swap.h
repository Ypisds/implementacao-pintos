#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <inttypes.h>
#include "threads/synch.h"

void swap_init(void);
extern struct lock swap_lock;
size_t swap_out(void *);
void reclamation(void *, size_t);


#endif /* vm/swap.h */