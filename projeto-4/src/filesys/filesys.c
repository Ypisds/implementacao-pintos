#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/synch.h"
#include "threads/thread.h"

struct lock filesys_lock;

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{ 
  lock_init(&filesys_lock);
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
/* Em filesys/filesys.c */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;
  char filename[NAME_MAX + 1];
  
  /* 1. Usa sua função nova para pegar o PAI */
  struct dir *parent_dir = parse_path_parent (name, filename);
  
  if (parent_dir == NULL) return false;

  /* 2. Extrai o setor do pai para passar para o filho */
  struct inode *parent_inode = dir_get_inode(parent_dir);
  block_sector_t parent_sector = inode_get_inumber(parent_inode);

  bool success = false;
  
  /* 3. Aloca o novo setor */
  if (free_map_allocate (1, &inode_sector)) 
    {
      if (is_dir) 
        {
           /* MÁGICA: Passa o parent_sector que descobrimos acima */
           success = dir_create (inode_sector, 0, parent_sector);
        }
      else 
        {
           success = inode_create (inode_sector, initial_size);
        }

      /* 4. Adiciona o nome no diretório pai */
      if (success)
        {
          success = dir_add (parent_dir, filename, inode_sector);
        }
      
      if (!success) 
         free_map_release (inode_sector, 1);
    }
    
  dir_close (parent_dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct inode *inode = NULL;

  /* 1. Navega pelo caminho (Absoluto ou Relativo) */
  /* dir_path_handler retorna true se achou, e preenche 'inode' */
  if (!dir_path_handler (name, &inode))
    {
      /* Caminho inválido ou arquivo não existe */
      return NULL;
    }

  /* 2. Cria a estrutura de arquivo associada ao inode */
  /* file_open retorna NULL se o inode for NULL, mas já checamos isso antes */
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char filename[NAME_MAX + 1];
  
  /* 1. Navega até o diretório pai e extrai o nome do arquivo final */
  struct dir *dir = parse_path_parent (name, filename);
  
  bool success = false;
  
  if (dir != NULL)
    {
      /* 2. Chama dir_remove no diretório correto */
      success = dir_remove (dir, filename);
      
      /* 3. Fecha o diretório pai */
      dir_close (dir); 
    }

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
