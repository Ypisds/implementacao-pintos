#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// static void
// syscall_handler (struct intr_frame *f) 
// {
//   int syscall_number = *(int *)f->esp;
//   switch(syscall_number) {
//     case SYS_HALT:
//       shutdown_power_off();
//       break;
//     case SYS_EXIT:
//       int status = *(int *)(f->esp+1);
//       (f->eax) = status;
//       process_exit();
//       break;

//     case SYS_WAIT:
//       tid_t child_id = *(tid_t *)(f->esp+1);
//       f->eax=child_id;
//       process_wait(); 
//       break;
    
//     case SYS_WRITE:
//       int fd = *(int *)(f->esp+1);
//       const void *buffer = *(void **)(f->esp+2);
//       unsigned size = *(unsigned *)(f->esp+3);

//       if(fd == 1) {
//         putbuf((char*)buffer, size);
//         f->eax = size;
//       }

//     break;

//   }
// }

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_number = *(int *)f->esp;

  switch(syscall_number) {
      case SYS_HALT:
        shutdown_power_off();
        break;
      case SYS_EXIT:
        int status = *(int *)(f->esp+1);
        (f->eax) = status;
        process_exit();
        break;
      case SYS_WAIT:
        tid_t child_id = *(tid_t *)(f->esp+1);
        f->eax=child_id;
        process_wait(); 
        break;
      case SYS_WRITE:
        int fd = *(int *)(f->esp+1);
        const void *buffer = *(void **)(f->esp+2);
        unsigned size = *(unsigned *)(f->esp+3);

        if(fd == 1) {
          putbuf((char*)buffer, size);
          f->eax = size;
        }

        break;
  }

  thread_exit();
}



