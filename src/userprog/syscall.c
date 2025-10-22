#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);
void exit(int status);

struct child_status* make_child_status(int status) {
  struct child_status *c = (struct child_status *)malloc(sizeof(struct child_status));

  c->child_id = thread_current()->tid;
  c->status=status;
 
  return c;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
      case SYS_EXEC: {
        char *cmd_line = (char*)*((int *)f->esp+1);
      
        
        tid_t child_id = exec(cmd_line);
      

        if(child_id == TID_ERROR) {
          f->eax = -1;
          break;
        }
        
        f-> eax = child_id;
        break;
      }
      case SYS_WAIT:{
        tid_t child_id = *((tid_t *)f->esp+1);
        int status = process_wait(child_id);
        f->eax = status;
        break;
      }
      case SYS_EXIT:{
        int status = *((int *)f->esp+1);
        (f->eax) = status;
        exit(status);
        break;
      }
      case SYS_WRITE:{
        
        int fd = *((int *)f->esp+1);
        const void *buffer = (const void *)*((int*)f->esp+2);
        unsigned size = *((int *)f->esp+3);

        if(fd == 1) {
          putbuf((char*)buffer, size);
          f->eax = size;
        }
        break;
      }
  }

}

void exit(int status) {
  struct child_status *c = get_child_status_by_tid(thread_current()->tid, thread_current()->parent);
  if(c != NULL ){
    c -> status = status;
    c -> has_exited = true;
    sema_up(&c-> wait_sema);
  }
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

tid_t exec(const char* cmd_line){

  if (cmd_line == NULL || !is_user_vaddr(cmd_line)) 
      return -1;

  lock_acquire(&filesys_lock);
  return process_execute(cmd_line);
  lock_release(&filesys_lock);
}



