#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/thread.h"

bool handle_absolute_path(const char *name, struct inode **inode);
bool processing_path(char * path_copy, struct inode** inode, struct dir* actual_dir);
bool handle_relative_path(const char *name, struct inode **inode);
bool handle_absolute_path(const char *name, struct inode **inode);

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
/* Creates a directory in the given SECTOR. 
   Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt, block_sector_t parent)
{
  
  if (!inode_create (sector, 0)) 
    return false;

  if (!inode_mark_as_dir (sector)) 
    return false;

  
  struct dir *dir = dir_open (inode_open (sector));
  if (dir == NULL) 
    return false;

  bool success = true;
  
  if (!dir_add (dir, ".", sector)) 
    success = false;

  if (!dir_add (dir, "..", parent)) 
    success = false; 

  dir_close (dir);
  return success;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

static bool
is_dir_empty (struct dir *dir)
{
  struct dir_entry e;
  off_t ofs;

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    {
      if (e.in_use)
        {
          if (strcmp (e.name, ".") != 0 && strcmp (e.name, "..") != 0)
            return false;
        }
    }
  return true;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return false;

  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* 2. Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  if (inode_is_dir (inode)) 
    {
      if (inode_get_inumber(inode) == ROOT_DIR_SECTOR) goto done; 


      struct dir *target_dir = dir_open (inode_reopen (inode));
      if (target_dir == NULL) goto done;

      bool is_empty = is_dir_empty (target_dir);
      

      dir_close (target_dir);

      if (!is_empty)
        goto done; 
    }

  
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}
/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}

bool
dir_path_handler(const char *name, struct inode **inode){ // passa um path e escreve no inode
  if(name[0] == '/') {
    return handle_absolute_path(name, inode);
  }else {
    return handle_relative_path(name, inode);
  }         
}

bool
handle_absolute_path(const char *name, struct inode **inode) {
  struct dir *actual_dir = dir_open_root();

  char *path_copy = malloc(strlen(name) + 1);
  if (path_copy == NULL) {
      dir_close(actual_dir);
      return false;
  }
  strlcpy(path_copy, name, strlen(name) + 1);

  return processing_path(path_copy, inode, actual_dir);
}

bool
handle_relative_path(const char *name, struct inode **inode) {
  struct dir *actual_dir;
  struct thread *t = thread_current();

  
  if (t->working_dir != NULL) {
      actual_dir = dir_reopen(t->working_dir);
  } else {
      actual_dir = dir_open_root();
  }


  if (actual_dir == NULL) return false;

  
  char *path_copy = malloc(strlen(name) + 1);
  if (path_copy == NULL) {
      dir_close(actual_dir);
      return false;
  }
  strlcpy(path_copy, name, strlen(name) + 1);

  return processing_path(path_copy, inode, actual_dir);
}

bool
processing_path(char * path_copy, struct inode** inode, struct dir* actual_dir){
  // criar função para o processamento
  char *token, *next_token, *save_ptr;
  token=strtok_r(path_copy, "/", &save_ptr);

  if(token == NULL) {
    *inode = dir_get_inode(actual_dir);
    inode_reopen(*inode); /* Incrementa ref count pois vamos fechar curr_dir */
    dir_close(actual_dir); 
    free(path_copy);
    return true; 
  }

  while(token != NULL) {
    if(!dir_lookup(actual_dir, token, inode)){
      dir_close(actual_dir);
      free(path_copy);
      return false;
    }
    
    next_token = strtok_r(NULL, "/", &save_ptr);

    if(next_token != NULL) {

      if(!inode_is_dir(*inode)) {
        inode_close(*inode);
        dir_close(actual_dir);
        *inode = NULL;
        free(path_copy);
        return false;
      }

      dir_close(actual_dir);
      actual_dir = dir_open(*inode); 
      token = next_token;
    }
    else {
      dir_close(actual_dir); 
      free(path_copy);
      return true;
    }
   
  }

  return false;
}

struct dir* parse_path_parent(char *path, char* filename) {
  struct dir* actual_dir;
  struct thread *t = thread_current();

  
  if (path[0] == '/' || t->working_dir == NULL) {
    actual_dir = dir_open_root();
  } else {
    
    actual_dir = dir_reopen(t->working_dir);
  }

  if (actual_dir == NULL) return NULL;

  
  char *path_copy = malloc(strlen(path) + 1);
  if (path_copy == NULL) {
      dir_close(actual_dir);
      return NULL;
  }
  strlcpy(path_copy, path, strlen(path) + 1);
  
  char *token, *next_token, *save_ptr;
  token = strtok_r(path_copy, "/", &save_ptr);

  
  if(token == NULL) {
    dir_close(actual_dir);
    free(path_copy);
    return NULL;
  }

  while(token != NULL) {
    
    next_token = strtok_r(NULL, "/", &save_ptr);

    if(next_token != NULL) {
      
      struct inode *inode = NULL;
      
      
      if(!dir_lookup(actual_dir, token, &inode)){ 
        dir_close(actual_dir);
        free(path_copy);
        return NULL; 
      }

      
      if(!inode_is_dir(inode)) {
        inode_close(inode);
        dir_close(actual_dir);
        free(path_copy);
        return NULL;
      }

      
      dir_close(actual_dir);
      actual_dir = dir_open(inode);
      token = next_token;
    }
    else {
      
      if (strlen(token) > NAME_MAX) {
        dir_close(actual_dir);
        free(path_copy);
        return NULL; 
      }
      
      strlcpy(filename, token, NAME_MAX + 1); 
      free(path_copy);
      return actual_dir; 
    }
  }

  return NULL;
}


