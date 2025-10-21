#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

static void syscall_handler (struct intr_frame *);
static struct lock filesys_lock;

void sys_exit(struct intr_frame *f);
void sys_wait(struct intr_frame *f);
void sys_create(struct intr_frame *f);
void sys_remove(struct intr_frame *f);
void sys_write(struct intr_frame *f);
void sys_read(struct intr_frame *f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_number = *(int *)f->esp;

  switch(syscall_number) {
      case SYS_HALT:
        shutdown_power_off();
        break;
      case SYS_EXIT:
        sys_exit(f);
        break;
      case SYS_WAIT:
        sys_wait(f);
        break;
      case SYS_CREATE:
        sys_create(f);
        break;
      case SYS_REMOVE:
        sys_remove(f);
        break;
      case SYS_WRITE:
        sys_write(f);
        break;
      case SYS_READ:
        sys_read(f);
        break;
  }

}


void sys_exit(struct intr_frame *f){
  int status = *((int *)f->esp+1);
  (f->eax) = status;
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}
void sys_wait(struct intr_frame *f){
  tid_t child_id = *((tid_t *)f->esp+1);
  f->eax=child_id;
  process_wait(child_id);
}
void sys_create(struct intr_frame *f){
  const char *file = (const char*)*((int*)f->esp+1);
  unsigned initial_size = *((int*)f->esp+2);

  lock_acquire(&filesys_lock);
  f->eax = filesys_create(file,initial_size);
  lock_release(&filesys_lock);
}
void sys_remove(struct intr_frame *f){
  const char *file = (const char*)*((int*)f->esp+1);

  lock_acquire(&filesys_lock);
  filesys_remove(file);
  lock_release(&filesys_lock);
}
void sys_write(struct intr_frame *f){
  int fd = *((int *)f->esp+1);
  const void *buffer = (const void *)*((int*)f->esp+2);
  unsigned size = *((int *)f->esp+3);

  if(fd == 1) {
    putbuf((char*)buffer, size);
    f->eax = size;
  }
}
void sys_read(struct intr_frame *f){
  int fd = *((int *)f->esp+1);
  uint8_t *buffer = (uint8_t *)*((int*)f->esp+2);
  unsigned size = *((int *)f->esp+3);

  if(fd == 0) {
    for(int keyCounter = 0; keyCounter < size; keyCounter++){
      buffer[keyCounter] = input_getc();
    }
    f->eax = size;
  }
}

