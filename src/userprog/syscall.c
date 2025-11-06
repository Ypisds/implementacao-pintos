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
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

struct child_status* make_child_status(int status) {
  struct child_status *c = (struct child_status *)malloc(sizeof(struct child_status));

  c->child_id = thread_current()->tid;
  c->status=status;
 
  return c;
}

void sys_exit(int status);
void sys_exec(struct intr_frame *f);
void sys_wait(struct intr_frame *f);
void sys_create(struct intr_frame *f);
void sys_remove(struct intr_frame *f);
void sys_write(struct intr_frame *f);
void sys_read(struct intr_frame *f);
void sys_open(struct intr_frame *f);
void sys_filesize(struct intr_frame *f);
void sys_seek(struct intr_frame *f);
void sys_tell(struct intr_frame *f);
void sys_close(struct intr_frame *f);
struct file *get_file_from_fd(int fd);

bool is_valid_user_ptr(const void *uaddr) {
    return (uaddr != NULL) &&
           is_user_vaddr(uaddr) &&
           pagedir_get_page(thread_current()->pagedir, uaddr) != NULL;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}


static void
syscall_handler (struct intr_frame *f)  
{
  if(!is_valid_user_ptr((int*)f->esp) || !is_valid_user_ptr((int*)f->esp+1)) {
    sys_exit(-1);
  }

  int syscall_number = *(int *)f->esp;

  switch(syscall_number) {
      case SYS_HALT:
        shutdown_power_off();
        break;
      case SYS_EXIT:
        int status = *((int *)f->esp+1);
        f->eax = status;
        sys_exit(status);
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
      case SYS_OPEN:
        sys_open(f);
        break;
      case SYS_FILESIZE:
        sys_filesize(f);
        break;
      case SYS_SEEK:
        sys_seek(f);
        break;
      case SYS_TELL:
        sys_tell(f);
        break;
      case SYS_CLOSE:
        sys_close(f);
        break;
      
  }

}

void sys_exit(int status){
  struct child_status *c = get_child_status_by_tid(thread_current()->tid, thread_current()->parent);
  if(c != NULL ){
    c -> status = status;
    sema_up(&c-> wait_sema);
  }
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}
void sys_exec(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  char *cmd_line = (char*)*((int *)f->esp+1);
  tid_t child_id;
  
  if(!is_valid_user_ptr(cmd_line))
    sys_exit(-1);

  
  child_id = process_execute(cmd_line);
  

  if(child_id == TID_ERROR) {
    f->eax = -1;
  } else {
    f-> eax = child_id;
  }
}
void sys_wait(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  tid_t child_id = *((tid_t *)f->esp+1);
  int status = process_wait(child_id);
  f->eax = status;
}
void sys_create(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1) || !is_valid_user_ptr((int*)f->esp+2))
    sys_exit(-1);
  const char *file = (const char*)*((int*)f->esp+1);
  unsigned initial_size = *((int*)f->esp+2);

  if(!is_valid_user_ptr(file)) sys_exit(-1);

  lock_acquire(&filesys_lock);
  f->eax = filesys_create(file,initial_size);
  lock_release(&filesys_lock);
}
void sys_remove(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  const char *file = (const char*)*((int*)f->esp+1);

  lock_acquire(&filesys_lock);
  filesys_remove(file);
  lock_release(&filesys_lock);
}
void sys_write(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1) || !is_valid_user_ptr((int*)f->esp+2) || !is_valid_user_ptr((int*)f->esp+3)){
    sys_exit(-1);
  }
  int fd = *((int *)f->esp+1);
  const void *buffer = (const void *)*((int*)f->esp+2);
  unsigned size = *((int *)f->esp+3);

  if(!is_valid_user_ptr(buffer)){
    sys_exit(-1);
  }
  

  if(fd == 1) {
    putbuf((char*)buffer, size);
    f->eax = size;
  }
  else if(fd > 1) {
    struct file *file = get_file_from_fd(fd);

    if(file != NULL) {
      lock_acquire(&filesys_lock);
      int off = file_write(file, buffer, size);
      lock_release(&filesys_lock);

      f-> eax = off;
    }
    else {
      f->eax = -1;
    }
  }
}
void sys_read(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1) || !is_valid_user_ptr((int*)f->esp+2) || !is_valid_user_ptr((int*)f->esp+3)){
    sys_exit(-1);
  }
  int fd = *((int *)f->esp+1);
  uint8_t *buffer = (uint8_t *)*((int*)f->esp+2);
  unsigned size = *((int *)f->esp+3);

  if(!is_valid_user_ptr(buffer)){
    sys_exit(-1);
  }

  if(fd == 0) {
    for(unsigned keyCounter = 0; keyCounter < size; keyCounter++){
      buffer[keyCounter] = input_getc();
    }
    f->eax = size;
  }
  else if(fd > 1) {
    struct file *file = get_file_from_fd(fd);

    if(file != NULL) {
      lock_acquire(&filesys_lock);
      int off = file_read(file, buffer, size);
      lock_release(&filesys_lock);

      f-> eax = off;
    }
    else {
      f->eax = -1;
    }
  }
}
void sys_open(struct intr_frame *f) {
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  const char *filename = (char *)*((int*)f->esp+1);

  if(!is_valid_user_ptr(filename)) sys_exit(-1);

  if (!is_user_vaddr(filename) || filename == NULL) {
    f->eax = -1;
    return;

  }

  lock_acquire(&filesys_lock);
  struct file *file = filesys_open(filename);
  lock_release(&filesys_lock);

  if(file == NULL) {
    f->eax = -1;
    return;
  }

  int fd;
  struct thread *cur = thread_current();
  for (fd = 2; fd < 128; fd++) {
    if (cur->fd_table[fd] == NULL)
        break;
  }
  if(fd == 128) {
    file_close(file);
    f->eax = -1;
  }
  else {
    thread_current()->fd_table[fd] = file;
    f->eax = fd;
  }
  
}

struct file *get_file_from_fd(int fd) {
  if(fd >=2 && fd < 128) {
    struct file* file = thread_current()->fd_table[fd];
    return file;
  }
  else {
    return NULL;
  }
}

void sys_filesize(struct intr_frame *f) {
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  int fd = *((int*)f->esp+1);

  struct file *file = get_file_from_fd(fd);

  if(file != NULL ){
    lock_acquire(&filesys_lock);
    int length = file_length(file);
    lock_release(&filesys_lock);

    f->eax = length;
  }
  else {
    f->eax = -1;
  }

}
void sys_seek(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1) ||!is_valid_user_ptr((int*)f->esp+1) )
    sys_exit(-1);
  int fd = *((int*)f->esp+1);
  unsigned position = (unsigned)*((int*)f->esp+2);

  struct file *file = get_file_from_fd(fd);

  if(file != NULL ){
    lock_acquire(&filesys_lock);
    file_seek(file,position);
    lock_release(&filesys_lock);
  } 
    
}
void sys_tell(struct intr_frame *f) {
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  int fd = *((int*)f->esp+1);

  struct file *file = get_file_from_fd(fd);

  if(file != NULL ){
    lock_acquire(&filesys_lock);
    int position = file_tell(file);
    lock_release(&filesys_lock);

    f->eax = position;
  } else {
    f-> eax = -1;
  }
}
void sys_close(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  int fd = *((int*)f->esp+1);

  struct file *file = get_file_from_fd(fd);

  if(file != NULL ){
    thread_current()->fd_table[fd] = NULL;
    lock_acquire(&filesys_lock);
    file_close(file);
    lock_release(&filesys_lock);

  }
}


