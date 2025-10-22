#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "userprog/syscall.h"

static void syscall_handler (struct intr_frame *);

struct child_status* make_child_status(int status) {
  struct child_status *c = (struct child_status *)malloc(sizeof(struct child_status));

  c->child_id = thread_current()->tid;
  c->status=status;
 
  return c;
}

void sys_exit(struct intr_frame *f);
void sys_exec(struct intr_frame *f);
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
  // /* Verifica se o esp do usuário é válido */
  // if (!is_user_vaddr(f->esp) || f->esp == NULL || pagedir_get_page(thread_current()->pagedir, f->esp) == NULL) {
  //   exit(-1);  /* Mata o processo */
  // }

  int syscall_number = *(int *)f->esp;

  switch(syscall_number) {
      case SYS_HALT:
        shutdown_power_off();
        break;
      case SYS_EXIT:
        sys_exit(f);
       break;
      case SYS_EXEC: 
        sys_exec(f);
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
  struct child_status *c = get_child_status_by_tid(thread_current()->tid, thread_current()->parent);
  if(c != NULL ){
    c -> status = status;
    c -> has_exited = true;
    sema_up(&c-> wait_sema);
  }
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}
void sys_exec(struct intr_frame *f){
  char *cmd_line = (char*)*((int *)f->esp+1);
  tid_t child_id;
  
  if (cmd_line == NULL || !is_user_vaddr(cmd_line)) 
      return -1;

  lock_acquire(&filesys_lock);
  child_id = process_execute(cmd_line);
  lock_release(&filesys_lock);

  if(child_id == TID_ERROR) {
    f->eax = -1;
  } else {
    f-> eax = child_id;
  }
}
void sys_wait(struct intr_frame *f){
  tid_t child_id = *((tid_t *)f->esp+1);
  int status = process_wait(child_id);
  f->eax = status;
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
    for(unsigned keyCounter = 0; keyCounter < size; keyCounter++){
      buffer[keyCounter] = input_getc();
    }
    f->eax = size;
  }
}

