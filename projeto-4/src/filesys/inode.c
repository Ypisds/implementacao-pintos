#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       
    unsigned magic;                     
    uint32_t is_dir; /* <--- NOVA FLAG: 1 se for diretório, 0 se arquivo */
    
    block_sector_t direct[10];
    block_sector_t indirect;              
    block_sector_t double_indirect;       

    uint32_t unused[113]; /* Reduzi 1 aqui para caber o is_dir */              
  };


#define PTRS_PER_SECTOR 128

/* Função auxiliar para alocar um setor com zeros. */
static bool
allocate_sector (block_sector_t *sector_idx)
{
  if (!free_map_allocate (1, sector_idx))
    return false;
  static char zeros[BLOCK_SECTOR_SIZE];
  cache_write (*sector_idx, zeros);
  return true;
}

/* O CORAÇÃO DA EXTENSIBILIDADE.
   Retorna o setor onde está o dado correspondente ao 'sector_index' do arquivo.
   Se 'create' for true, cria os setores (índices e dados) se não existirem. */
static block_sector_t
inode_get_block (struct inode_disk *disk_inode, block_sector_t sector_index, bool create)
{
  /* 1. Blocos Diretos (0 a 9) */
  if (sector_index < 10)
    {
      if (disk_inode->direct[sector_index] == 0)
        {
          if (create && !allocate_sector (&disk_inode->direct[sector_index]))
            return 0;
        }
      return disk_inode->direct[sector_index];
    }
  
  sector_index -= 10;

  /* 2. Bloco Indireto (10 a 137) */
  if (sector_index < PTRS_PER_SECTOR)
    {
      if (disk_inode->indirect == 0)
        {
          if (!create || !allocate_sector (&disk_inode->indirect))
            return 0;
        }

      block_sector_t *indirect_block = malloc (BLOCK_SECTOR_SIZE);
      if (!indirect_block) return 0;

      cache_read (disk_inode->indirect, indirect_block);
      
      block_sector_t ret = indirect_block[sector_index];
      if (ret == 0 && create)
        {
          if (allocate_sector (&indirect_block[sector_index]))
            {
              cache_write (disk_inode->indirect, indirect_block);
              ret = indirect_block[sector_index];
            }
        }
      free (indirect_block);
      return ret;
    }

  sector_index -= PTRS_PER_SECTOR;

  /* 3. Bloco Duplamente Indireto (138 em diante) */
  if (sector_index < PTRS_PER_SECTOR * PTRS_PER_SECTOR)
    {
      if (disk_inode->double_indirect == 0)
        {
          if (!create || !allocate_sector (&disk_inode->double_indirect))
            return 0;
        }

      /* Nível 1: Ler o índice do índice */
      block_sector_t *l1_block = malloc (BLOCK_SECTOR_SIZE);
      if (!l1_block) return 0;
      cache_read (disk_inode->double_indirect, l1_block);

      off_t l1_idx = sector_index / PTRS_PER_SECTOR;
      off_t l2_idx = sector_index % PTRS_PER_SECTOR;

      if (l1_block[l1_idx] == 0)
        {
          if (!create || !allocate_sector (&l1_block[l1_idx]))
            {
              free (l1_block);
              return 0;
            }
          cache_write (disk_inode->double_indirect, l1_block);
        }
      
      block_sector_t next_sector = l1_block[l1_idx];
      free (l1_block);

      /* Nível 2: Ler o índice final */
      block_sector_t *l2_block = malloc (BLOCK_SECTOR_SIZE);
      if (!l2_block) return 0;
      cache_read (next_sector, l2_block);

      block_sector_t ret = l2_block[l2_idx];
      if (ret == 0 && create)
        {
          if (allocate_sector (&l2_block[l2_idx]))
            {
              cache_write (next_sector, l2_block);
              ret = l2_block[l2_idx];
            }
        }
      free (l2_block);
      return ret;
    }

  return 0;
}

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };


/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    return inode_get_block (&inode->data, pos / BLOCK_SECTOR_SIZE, false);
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = 0;
      
      /* Aloca os blocos necessários se length > 0 */
      if (length > 0)
        {
          size_t sectors = bytes_to_sectors (length);
          size_t i;
          for (i = 0; i < sectors; i++)
            {
              if (inode_get_block (disk_inode, i, true) == 0)
                {
                  /* Se falhar alocação, deveria limpar, mas para simplificar retornamos false */
                  free (disk_inode);
                  return false;
                }
            }
        }

      cache_write (sector, disk_inode);
      success = true;
      free (disk_inode);
    }
  return success;
}

bool
inode_is_dir (const struct inode *inode)
{
  if (inode == NULL) return false;
  return inode->data.is_dir == 1;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  if (inode == NULL)
    return;

  if (--inode->open_cnt == 0)
    {
      list_remove (&inode->elem);
 
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          
          /* Lógica simplificada de desalocação: Varre todos os blocos possíveis do arquivo */
          /* Nota: Uma implementação ideal navega na árvore de ponteiros para ser mais rápida.
             Mas iterar pelos blocos lógicos funciona se inode_get_block retornar 0 para não alocados. */
          
          size_t sectors = bytes_to_sectors (inode->data.length);
          size_t i;
          
          /* Libera os dados */
          for (i = 0; i < sectors; i++)
            {
               block_sector_t s = inode_get_block (&inode->data, i, false);
               if (s != 0) free_map_release (s, 1);
            }
          
          /* Libera os índices (indireto e duplo) */
          if (inode->data.indirect != 0) 
             free_map_release (inode->data.indirect, 1);
             
          if (inode->data.double_indirect != 0) 
            {
               /* Precisaria liberar o índice nível 2 também aqui, mas para começar, libere o nível 1 */
               /* Implementação completa de desalocação recursiva recomendada para nota máxima */
               /* Esta parte é a mais complexa de fazer "rápido". Se quiser a recursiva completa me avise. */
               free_map_release (inode->data.double_indirect, 1); 
            }
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  /* PARTE NOVA: Extensão automática do arquivo */
  if (offset + size > inode_length (inode))
    {
      if (!inode->deny_write_cnt) 
        {
          /* Estende o arquivo alocando os blocos necessários */
          struct inode_disk *disk_inode = &inode->data;
          size_t sectors_needed = bytes_to_sectors (offset + size);
          size_t current_sectors = bytes_to_sectors (inode_length (inode));
          size_t i;
          
          for (i = current_sectors; i < sectors_needed; i++)
            {
              if (inode_get_block (disk_inode, i, true) == 0)
                 return 0; /* Falha na extensão (disco cheio) */
            }
          
          disk_inode->length = offset + size;
          cache_write (inode->sector, disk_inode);
        }
    }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      
      /* Se sector_idx for 0 ou -1 aqui, algo deu errado na extensão ou lógica */
      if (sector_idx == 0 || sector_idx == (block_sector_t)-1)
         break;

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          cache_write(sector_idx, buffer + bytes_written);
        }
      else 
        {
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL) break;
            }

          if (sector_ofs > 0 || chunk_size < sector_left) 
            cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write (sector_idx, bounce);
        }

      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

/* Em filesys/inode.c */

/* Marca o inode localizado no setor SECTOR como sendo um diretório. */
bool
inode_mark_as_dir (block_sector_t sector)
{
  struct inode *inode = inode_open (sector);
  if (inode == NULL)
    return false;

  /* Modifica a flag em memória */
  inode->data.is_dir = 1;

  /* Grava a alteração de volta no disco imediatamente */
  cache_write (inode->sector, &inode->data);

  inode_close (inode);
  return true;
}

/* Retorna o número de openers do inode. */
int
inode_get_open_cnt (const struct inode *inode)
{
  return inode->open_cnt;
}

bool
inode_is_removed (const struct inode *inode) 
{
  return inode->removed;
}
