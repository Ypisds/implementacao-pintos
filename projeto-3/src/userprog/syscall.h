#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>

void syscall_init (void);
bool verify_buffer(void*, unsigned, bool);

#endif /* userprog/syscall.h */
