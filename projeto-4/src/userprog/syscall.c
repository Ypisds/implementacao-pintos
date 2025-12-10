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
#include "filesys/directory.h"
#include "filesys/inode.h"

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
bool sys_chdir(struct intr_frame *f);
bool sys_mkdir(struct intr_frame *f);
bool sys_readdir(struct intr_frame *f);
bool sys_isdir(struct intr_frame *f);
int sys_inumber(struct intr_frame *f);
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
      case SYS_CHDIR:
        f->eax = sys_chdir(f) ? 1 : 0;
        break;
      case SYS_MKDIR:
        f->eax = sys_mkdir(f) ? 1 : 0;
        break;
      case SYS_READDIR:
        f->eax = sys_readdir(f) ? 1 : 0;
        break;
      case SYS_ISDIR:
        f->eax = sys_isdir(f) ? 1 : 0;
        break;
      case SYS_INUMBER:
        f->eax = sys_inumber(f);
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
  for(int i = 0; i < 4; i++){
    if(!is_valid_user_ptr((uint8_t*)f->esp+4+i)) sys_exit(-1);
  }
  char *cmd_line = (char*)*((int *)f->esp+1);

  char verification = 'a';
  char *pointer = cmd_line;
  while(verification != '\0'){
    if(!is_valid_user_ptr(pointer)) sys_exit(-1);
    verification = *pointer;
    pointer += 1;
  }
  
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

  if (file[0] != '/') { 
      struct dir *cwd = thread_current()->working_dir;
      
      if (cwd != NULL && inode_is_removed(dir_get_inode(cwd))) {
          f->eax = 0; 
          lock_release(&filesys_lock);
          return;
      }
  }
  
  f->eax = filesys_create(file,initial_size, false);
  lock_release(&filesys_lock);
}
void sys_remove(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  const char *file = (const char*)*((int*)f->esp+1);

  lock_acquire(&filesys_lock);
  bool status = filesys_remove(file);
  lock_release(&filesys_lock);
  f -> eax = status ? 1 : 0;
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
void
sys_open (struct intr_frame *f)
{
  if(!is_valid_user_ptr((int*)f->esp+1)){
    sys_exit(-1);
  }
  
  char * file_name = *((int*)f->esp+1);

  if(!is_valid_user_ptr(file_name)) sys_exit(-1);

  
  if (file_name == NULL || !is_user_vaddr(file_name)) {
      sys_exit(-1);
  }

  if(strlen(file_name) == 0) {
    f->eax = -1;
    return;
  }

  if (file_name[0] != '/') {
      struct dir *cwd = thread_current()->working_dir;
      if (cwd != NULL && inode_is_removed(dir_get_inode(cwd))) {
          f->eax = -1;
          return;
      }
  }

  struct thread *cur = thread_current ();
  
  
  int fd = -1;
  for (int i = 2; i < 128; i++) {
      if (cur->fd_table[i] == NULL) {
          fd = i;
          break;
      }
  }
  
  
  if (fd == -1) {
    f-> eax = -1;
    return;
  } 

  
  struct inode *inode = NULL;
  
  
  if (!dir_path_handler(file_name, &inode)) {
      f->eax = -1; 
      return;
  }

  if (inode_is_removed(inode)) {
      inode_close(inode); 
      return;
  }

  
  struct file_desc *fdesc = malloc(sizeof(struct file_desc));
  if (fdesc == NULL) {
      inode_close(inode); 
      f->eax = -1;
      return;
  }

  
  if (inode_is_dir(inode)) {
      
      fdesc->dir = dir_open(inode);
      fdesc->file = NULL;
      fdesc->is_dir = true;
      
      
      if (fdesc->dir == NULL) {
          free(fdesc);
          f->eax = -1;
          return;
      }
  } else {
      
      fdesc->file = file_open(inode);
      fdesc->dir = NULL;
      fdesc->is_dir = false;

      
      if (fdesc->file == NULL) {
          free(fdesc);
          f->eax = -1;
          return;
      }
  }

  
  cur->fd_table[fd] = fdesc;
  f->eax = fd;
}

struct file *get_file_from_fd(int fd) {
  if(fd >=2 && fd < 128) {
    struct file_desc* file_desc = thread_current()->fd_table[fd];
    if(file_desc == NULL || file_desc->is_dir) return NULL;
    struct file* file = file_desc->file;
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

  struct thread* cur = thread_current();

  
  if (fd < 2 || fd >= 128) return;

  
  struct file_desc *fdesc = cur->fd_table[fd];

  if (fdesc != NULL) {
    lock_acquire(&filesys_lock);
    
    
    if (fdesc->is_dir) {
        dir_close(fdesc->dir);
    } else {
        file_close(fdesc->file);
    }
    
    lock_release(&filesys_lock);

    
    free(fdesc);             
    cur->fd_table[fd] = NULL; 
  }
}

bool sys_chdir(struct intr_frame *f){
  const char *dir_name = *((int*)f->esp+1);
  struct inode *dir_inode = NULL;
  
  if(dir_path_handler(dir_name, &dir_inode)) {
    if(!inode_is_dir(dir_inode)){
      inode_close(dir_inode);
      return false;
    }
    
    struct dir *old_dir = thread_current()->working_dir;
    thread_current()->working_dir = dir_open(dir_inode);

    if (old_dir != NULL) 
    {
       dir_close(old_dir);
    }

    return true;
  }

  return false;
}

bool sys_mkdir(struct intr_frame *f){
  const char *path = *((int*)f->esp+1);

  return filesys_create(path, 0, true);
}

bool sys_readdir(struct intr_frame *f){
  int fd = *((int*)f->esp+1);
  char *name = *((int*)f->esp+2);

  if(fd < 2 || fd >= 128) return false;

  struct file_desc* file_desc = thread_current()->fd_table[fd];

  if(file_desc == NULL || !file_desc->is_dir) return false;

  lock_acquire(&filesys_lock);
  
  bool success;
  
  while (true) 
  {
      success = dir_readdir(file_desc->dir, name);
      
      if (!success) {
          break; 
      }
      if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
          break;
      }
  }

  lock_release(&filesys_lock);

  return success;
  
}

bool sys_isdir(struct intr_frame *f) {

  int fd = *((int*)f->esp+1);

  if(fd < 2 || fd >= 128) return false;

  struct file_desc* file_desc = thread_current()->fd_table[fd];

  if(file_desc == NULL) return false;

  return file_desc -> is_dir;

}

int sys_inumber(struct intr_frame *f) {
  int fd = *((int*)f->esp+1);

  if(fd < 2 || fd >= 128) return -1;

  struct file_desc* file_desc = thread_current()->fd_table[fd];

  if(file_desc == NULL) return -1;

  struct inode *inode = NULL;

  if (file_desc->is_dir) {
      inode = dir_get_inode(file_desc->dir);
  } else {
      inode = file_get_inode(file_desc->file);
  }

  return (int) inode_get_inumber(inode);
}


