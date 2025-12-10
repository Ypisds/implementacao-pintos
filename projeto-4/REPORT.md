# Projeto 4 - Filesys

Equipe:

Thiago Henrique Rezende Brito(thrb)

Rodrigo Pontes de Oliveira Lima (rpol)

Vitor Manoel de Melo Silva (vmms)

## Parte 1 - Indexação de Arquivos:

No PintOS, inicialmente os arquivos são salvos no disco como sequências de blocos contíguos. Nesse parte, nós implementamos a indexação de arquivos de forma que eles possam ser salvos de forma fragmentada usando
blocos diretos, indiretos e duplamente indiretos.

### Mudanças no `inode_disk`:

Na struct `inode_disk`, foram adicionadas a posição inicial dos blocos diretos, do bloco indireto e do bloco duplamente indireto dos inodes. No total, são 10 blocos diretos, 1 bloco indireto e 1 bloco duplamente indireto. Também foi adicionada a flag `is_dir` para indicar que um inode é referente a um diretório.

```C
struct inode_disk
  {
    off_t length;                       
    unsigned magic;                     
    uint32_t is_dir;
    
    block_sector_t direct[10];
    block_sector_t indirect;              
    block_sector_t double_indirect;       

    uint32_t unused[113];           
};
```

### Funções `inode_create` e `inode_get_block`:

A função `inode_create` foi modificada para lidar com a nova estrutura do inode. 

Foi criada uma função auxiliar `inode_get_block` que implementa a lógica de obter um bloco lidando com a estrutura de blocos diretos e indiretos do inode.

No `inode_get_block`, a função recebe o inode a ser acessado, o índice do setor desejado e a flag `create` que indica a função para criar o setor caso ele não exista. Inicialmente, é verificado se o índice `sector_index` é menor que 10 e, caso seja, o bloco direto respectivo ao índice é retornado. Caso seja maior que 10 mas menor que `PTRS_PER_SECTOR`, o bloco indireto é acessado e a função retorna o setor do bloco indireto indexado por `sector_index-10`. Caso o `sector_index` seja maior que `PTRS_PER_SECTOR`, o bloco duplamente indireto é acessado, e logo em seguida o bloco indireto no índice `sector_index/128` é acessado e  a função retorna o setor indexado nesse bloco indireto por `sector_index-10 % PTRS_PER_SECTOR`. Se algum erro ocorrer, a função retorna 0.

Em `inode_create`, a função `inode_get_block` é chamada no loop para a criação dos setores recebendo a flag `create` como `true`.

```C
static block_sector_t
inode_get_block (struct inode_disk *disk_inode, block_sector_t sector_index, bool create)
{
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

  if (sector_index < PTRS_PER_SECTOR * PTRS_PER_SECTOR)
    {
      if (disk_inode->double_indirect == 0)
        {
          if (!create || !allocate_sector (&disk_inode->double_indirect))
            return 0;
        }

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
```

```C
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

      if (length > 0)
        {
          size_t sectors = bytes_to_sectors (length);
          size_t i;
          for (i = 0; i < sectors; i++)
            {
              if (inode_get_block (disk_inode, i, true) == 0)
                {
                  
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
```

### Mudança na função `inode_write_at`:

Nos projetos passados, a função de escrita do inode não conseguia escrever em posições após o EOF, já que o crescimento de arquivo não estava implementado. Agora a função `inode_write_at` implementa o crescimento do arquivo utilizando a estratégia de alocar todos os blocos entre a posição da escrita e o EOF.

```C
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  
  if (offset + size > inode_length (inode))
    {
      if (!inode->deny_write_cnt) 
        {
          
          struct inode_disk *disk_inode = &inode->data;
          size_t sectors_needed = bytes_to_sectors (offset + size);
          size_t current_sectors = bytes_to_sectors (inode_length (inode));
          size_t i;
          
          for (i = current_sectors; i < sectors_needed; i++)
            {
              if (inode_get_block (disk_inode, i, true) == 0)
                 return 0; 
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
```

# Parte 2 - Diretórios, Subdiretórios e Pathnames:

Nos projetos passados do PintOS, os processos só podiam criar arquivos dentro do diretório raiz, que continha todos os arquivos do sistema operacional. Agora, depois de implementar o projeto 4, eles podem criar subdiretórios e percorrer por esses subdiretórios através do _pathname_. Para isso, os processos têm acesso a novas _syscalls_, inclusindo o _sys\_chdir_, _sys\_mkdir_ e outras, além das adaptações das já existentes para abrir arquivos ou diretórios através do _pathname_.

### Implementando subdiretórios:

Diretórios já são estruturas nativas do pintOS. Cada diretório tem um _inode_ associado e cada entrada tem um settor do disco associado, bem como um nome e um booleano para indicar se está sendo utilizado. É importante ressaltar que, como diretórios também são considerados arquivos, as implementações de extensibilidade também fazem efeito nos diretórios.

```C
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

```

Para criar um subdiretório, precisamos de duas funções essenciais: `filesys_create()`, `dir_create()` e `dir_add()`.

```C
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;
  char filename[NAME_MAX + 1];
  
  
  struct dir *parent_dir = parse_path_parent (name, filename); // resolve o pathname
  
  if (parent_dir == NULL) return false;

  
  struct inode *parent_inode = dir_get_inode(parent_dir);
  block_sector_t parent_sector = inode_get_inumber(parent_inode);

  bool success = false;
  
  
  if (free_map_allocate (1, &inode_sector)) 
    {
      if (is_dir) 
        {
           success = dir_create (inode_sector, 0, parent_sector);
        }
      else 
        {
           success = inode_create (inode_sector, initial_size);
        }

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

bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  
  if (lookup (dir, name, NULL, NULL))
    goto done;


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
```

Em resumo, podemos passar uma flag `is_dir` para o `filesys_create()`, que irá chamar a função `dir_create()`. Nessa última, será criado um  _inode_, com a flag _is\_dir_ assinalada como _true_. Também é considerado a criação dos diretórios "." e "..", já que o pai é passado como parâmetro.

Em seguida, sendo bem sucedida a criação do arquivo ou do diretório, utilizamos o `dir_add()` para adicionar o arquivo ou subdiretório no pai.

### Mudança na fd_table:

Na `struct thread`, mudamos a `ffd_table` para lidar com o caso de diretórios que podem ser salvos e descritos por _fd_.

```C
struct thread
  {
    [...]

#ifdef USERPROG

    [...]
    
    struct file_desc* fd_table[128];
    int next_fd;
    struct file* executable_file;
    
#endif

   struct dir* working_dir;

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

struct file_desc {
    struct file *file;   
    struct dir *dir;     
    bool is_dir;         
};
```

A primeira mudança notável é a presença do _working\_dir_. Basicamente, guarda um diretório aberto que representa o diretório atual do processo.

A segunda mudança é a utilização da `struct file_desc` na `fd_table`. Essa mudança faz com que tenha a possibilidade de armazenas tanto diretórios quanto arquivos na `fd_table`, distinguidos pelo "is_dir". 

### Novas sys_calls:

Criamos novas _sys\_calls_ e atualizamos algumas já existentes desde o projeto 2 para lidar com subdiretórios e suas manipulações.

- `bool sys_chdir(struct intr_frame *f)`: Uma _syscall_ responsável por procurar um diretório válido e alterar o diretório atual do processo(working_dir).

```C
bool sys_chdir(struct intr_frame *f){
  const char *dir_name = *((int*)f->esp+1);
  struct inode *dir_inode = NULL;
  
  if(dir_path_handler(dir_name, &dir_inode)) { // dir_path_handler resolve o pathname
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
```

- `bool sys_mkdir(struct intr_frame *f)`: Busca o path e o encaminha para o `filesys_create`. Como a intenção é cria um diretório vazio, passamos o tamanho 0 e a flag `is_dir` como _true_.

```C
bool sys_mkdir(struct intr_frame *f){
  const char *path = *((int*)f->esp+1);

  return filesys_create(path, 0, true);
}
```

- `bool sys_readdir(struct intr_frame *f)`: Recebe um _fd_ e um _pathname_ como argumento. É a partir daqui que fica clara a importância da nova `fd_table` criada. É utilizada a função `dir_readdir()` nativa do PintOS, que lê um diretório o próximo diretório e escreve o seu nome em `name`. Uma observação é que ignoramos o "." e o "..", já que isso pode causar um loop em que o diretório fica lendo a si mesmo infinitamente.

```C
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
```

- `bool sys_isdir(struct intr_frame *f)`: Verifica se o arquivo salvo em _fd_ é um diretório. Essa função basicamente só olha a flag `is_dir` em `file_desc`.

```C
bool sys_isdir(struct intr_frame *f) {

  int fd = *((int*)f->esp+1);

  if(fd < 2 || fd >= 128) return false;

  struct file_desc* file_desc = thread_current()->fd_table[fd];

  if(file_desc == NULL) return false;

  return file_desc -> is_dir;

}
```

- `int sys_inumber(struct intr_frame *f)`: Pegamos um _fd_ que foi passado como argumento e, a partir daí, recuperamos o _file_ ou o _dir_. Qualquer que seja, pegamos o seu _inode_ e, com o auxílio de `inode_get_number()`, retornamos o _inumber_.

```C
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
```

### Alterando as syscalls antigas:

As _syscalls_ mais alteradas foram aquelas que mexiam com arquivos, já que devem considerar diretórios e subdiretórios agora.

- `struct file *get_file_from_fd(int fd)`: É uma função auxiliar muito utilizada nas outras _syscalls_. Agora ela considera a possibilidade de ter diretórios no _fd_, então retorna _NULL_.

```C
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
```

- `sys_open (struct intr_frame *f)`: Considera um _pathname_ agora. Não aceita _pathnames_ vazios e trata tanto os casos de diretórios quanto de arquivos e obtém o _fd_.

```C
void
sys_open (struct intr_frame *f)
{
  [...]

  char * file_name = *((int*)f->esp+1);


  if(strlen(file_name) == 0) { // Não aceita string vazia ""
    f->eax = -1;
    return;
  }

  if (file_name[0] != '/') { // Verifica se o working_dir não está como removido, já que está utilizando caminho relativo
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
  
  
  if (!dir_path_handler(file_name, &inode)) { // resolve o path
      f->eax = -1; 
      return;
  }

  if (inode_is_removed(inode)) { // verifica se está removido o inode. 
      inode_close(inode); 
      return;
  }

  
  struct file_desc *fdesc = malloc(sizeof(struct file_desc));
  if (fdesc == NULL) {
      inode_close(inode); 
      f->eax = -1;
      return;
  }

  
  if (inode_is_dir(inode)) { // caso o inode for o diretório
      
      fdesc->dir = dir_open(inode);
      fdesc->file = NULL;
      fdesc->is_dir = true;
      
      
      if (fdesc->dir == NULL) {
          free(fdesc);
          f->eax = -1;
          return;
      }
  } else { // caso não seja o diretório.
      
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
```

- `void sys_remove(struct intr_frame *f)`: A única mudança feita nessa _syscall_ foi na função auxiliar `filesys_remove()`. O `filesys_remove()` resolve o _pathname_ e deleta o arquivo especificado.

```C
void sys_remove(struct intr_frame *f){
  if(!is_valid_user_ptr((int*)f->esp+1))
    sys_exit(-1);
  const char *file = (const char*)*((int*)f->esp+1);

  lock_acquire(&filesys_lock);
  bool status = filesys_remove(file);
  lock_release(&filesys_lock);
  f -> eax = status ? 1 : 0;
}

bool
filesys_remove (const char *name) 
{
  char filename[NAME_MAX + 1];

  struct dir *dir = parse_path_parent (name, filename); // trata o path, retorna o diretório pai e retorna o filename.
  
  bool success = false;
  
  if (dir != NULL)
    {
      success = dir_remove (dir, filename);

      dir_close (dir); 
    }

  return success;
}
```

- `void sys_close(struct intr_frame *f)`: A mudança principal está em identificar se é um diretório ou um arquivo que deve ser removido. Caso seja um diretório, chama o `dir_close()`, que verifica se o diretório está vazio, não pode deletar o diretório raiz nem os diretórios "." e ".." diretamente.

```C
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

```

### Algumas decisões de projeto:

- Diretórios abertos podem ser removidos. Assim, os _inodes_ desses diretórios ficarão com uma flag de "removido" como _true_. Como consequência, nenhum arquivo poderá abrí-los e quando o _open\_cnt_ for menor do que zero, o diretório/arquivo finalmente será deletado.
- Diretórios de trabalho de outros processos podem ser removidos, já que isso não o afeta caso ele esteja utilizando.

### Pathname
Para a implementação do caminhos de diretórios (e arquivos) utilizamos o handler `dir_path_handler` que verifica se o pathname é relativo (referente ao diretório atual) ou absoluto (referente ao diretório raiz) a partir da verificação do começo do pathname
```C
bool
dir_path_handler(const char *name, struct inode **inode){ // passa um path e escreve no inode
  if(name[0] == '/') {
    return handle_absolute_path(name, inode);
  }else {
    return handle_relative_path(name, inode);
  }         
}
```
Se o pathname for absoluto, encaminhamos para outra função de handler, `handle_absolute_path`, que prepara o ambiente de diretório para o processamento do pathname ao considerar o diretório atual como sendo o diretório raiz, além de realizar verificações importantes para garantir que não há erros no pathname passado como input.
```C
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
```
O mesmo é realizado para pathnames relativos, onde `handle_relative_path` considera o diretório atual como o diretório de trabalho do processo (se falhar, devemos abrir a partir do diretório raiz) e realiza as verificações necessárias do pathname.
```C
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
```
Ambas as funções chamam no final a função responsável pelo processamento do pathname, para que eventualmente encontremos o inode correto para o caminho solicitado. Essa função possui retorno booleano, com a saída relacionada a falha ou sucesso no processo de encontrar o caminho (e o inode) correto. É importante ressaltar que essa função **não** considera o caminho de arquivos, somente de diretórios.
```C
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
```
- A condição `if(token == NULL)` é utilizada para checar se o caminho (pathname) após o `/` é vazio. Se for, obtemos o inode atual, e reabrimos o inode antes de fechar o diretório atual.
- O laço `while(token != NULL)` realiza um `dir_lookup(actual_dir, token, inode)` para o token atual, verificando se o mesmo existe.Se não existir, não estamos trabalhando com um diretório, sendo uma situação de erro. Já se existir, muda o argumento `inode` da função para o inode relacionado ao novo diretório, obtêm o próximo token em `next_token`, e realiza outra checagem
  - A checagem `if(next_token != NULL)` verifica se o p
não for ,
Nessa parte, queremos imp fechamos os inodes e diretórios atuais, e atualizamos `token` com o próximo token para continuar o laço, se o próximo token for nulo, fecha o diretório atual e retorna `true`.
Por último, temos a função `struct dir* parse_path_parent`, que é bastante similar às anteriores, com a única diferença sendo que ela ela retorna o diretório pai de um arquivo, e também o nome do arquivo/subdire
tório em `filename` à chamadas de função
```C
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
```lementar a _cache_, responsável por evitar múltiplos acessos ao disco ao carregar blocos que estão sendo utilizados na memória. Isso faz com que todo o processo de leitura e escrita seja mais rápido, otimizando a experiência do usuário com o sistema operacional. A _cache_ será colocada como uma camada intermediária para o acesso ao disco. 

### Criando arquivos cache.c e cache.h:

Para implementar o cache, vamos criar os arquivos `cache.c` e `cache.h`

```C
// cache.h
#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"

void cache_init (void);
void cache_read (block_sector_t sector, void *buffer);
void cache_write (block_sector_t sector, const void *buffer);
void cache_flush (void);

#endif
```

Nesse _header_, estão expostas as funções que serão utilizadas em outros arquivos, com uma breve explicação de cada uma logo a seguir:
- `cache_init()`: Responsável por inicializar variáveis essenciais para o funcionamento da cache. Isso inclui _locks_, _conds_ e listas, além das _threads_ que serão utilizadas assíncronamente para o _Read-Ahead_ e o _Write-Behind_.
- `cache_read(block_sector_t sector, void *buffer)`: Serve para ler uma entrada da cache e copiar para o _buffer_, caso tenha um. Se não tiver, pode-se considerar uma leitura antecipada, que serve para antecipar os dados que o usuário pode pedir, otimizando todo o processo de leitura.
- `cache_write(block_sector_t sector, const void *buffer)`: Carrega dados que o usuário passou pelo _buffer_ para uma entrada do _cache_.
- `cache_flush()`: Serve para salvar todas as entradas `dirty` no disco.

### Structs e inicialização das variáveis:

Vamos detalhar um pouco mais a nossa _cache_:

```C
#define CACHE_SIZE 64

struct cache_entry {
    block_sector_t sector;  
    bool valid;             
    bool dirty;             
    bool accessed;          
    uint8_t data[BLOCK_SECTOR_SIZE]; 
};

static struct cache_entry cache[CACHE_SIZE];
static struct lock cache_lock;

[...]


```

A _cache_ é um conjunto de 64 entradas, ou seja, um _array_ de tamanho 64 do tipo _cache\_entry_. A gente declara a _cache_ um pouco abaixo da `struct cache_entry`. Também temos um _lock_ para garantir a integridade dos dados, tendo em vista a concorrência de _threads_.

Os campos principais são:
- `block_sector_t sector`: Indica qual setor do disco armazena a informação que está carregada nessa entrada.
- `bool valid`: Indica se uma entrada da _cache_ está em uso.
- `bool dirty`: Indica que há uma discrepância entre os dados na _cache_ e no disco.
- `bool accessed`: Indica que a entrada da _cache foi acessada recentemente(Algoritmo da Segunda Chance)
- `uint8_t data[BLOCK_SECTOR_SIZE]`: São os dados

Em seguida, temos algumas outras estruturas essenciais para o _Read-Ahead_ e o _Write-Behing_:

```C
static struct list read_ahead_list; 
static struct lock read_ahead_lock; 
static struct condition read_ahead_cond; 

struct read_ahead_entry {
    block_sector_t sector;
    struct list_elem elem;
};


static void cache_write_behind_thread (void *aux UNUSED);
static void cache_read_ahead_thread (void *aux UNUSED);
void cache_trigger_read_ahead (block_sector_t sector);
```

Essas funções e estruturas serão explicadas posteriormente.

### Principais funções do cache.c:

- `cache_init()`: Responsável pela inicialização de listas, _locks_ e _conds_. Também cria as threads para o _write-begind_ e o _read-ahead_.

```C
void
cache_init (void) {
    lock_init(&cache_lock);
    list_init(&read_ahead_list);
    lock_init(&read_ahead_lock);
    cond_init(&read_ahead_cond);
    
    thread_create("cache_wb", PRI_DEFAULT, cache_write_behind_thread, NULL);
    thread_create("cache_ra", PRI_DEFAULT, cache_read_ahead_thread, NULL);
}
```

- `cache_get_index(block_sector_t sector)`: Responsável por encontrar uma entrada da _cache_ que não foi utilizada recentemente. É nessa função que se implementa o Algoritmo de Segunda Chance.

```C
static int clock_hand = 0; // salva a posição atual para implementar uma lista circular

static int
cache_get_index (block_sector_t sector)
{
    for (int i = 0; i < CACHE_SIZE; i++) { // Verifica se o sector já está na cache, devido ao read-ahead
        if (cache[i].valid && cache[i].sector == sector) {
            cache[i].accessed = true; 
            return i;
        }
    }

    while (true) {
        if (!cache[clock_hand].valid) { 
            return clock_hand;
        }

        if (cache[clock_hand].accessed) { // se foi acessado recentemente, coloca como false(segunda chance)
            cache[clock_hand].accessed = false;
        } else {
            if (cache[clock_hand].dirty) { // Se estiver sujo, salva no disco
                block_write(fs_device, cache[clock_hand].sector, cache[clock_hand].data);
            }
            return clock_hand;
        }
        clock_hand = (clock_hand + 1) % CACHE_SIZE; // Garante que nunca vai acessar uma posição fora do array.
    }
}
```

- `cache_read(block_sector_t sector, void *buffer)`: Lê o setor do _cache_ e escreve no _buffer_. Se esse setor não estiver no _cache_, busca em disco.A função `cache_trigger_read_ahead(sector + 1)` é acionada quando uma leitura é feita para o processo e serve para colocar outros setores do disco na lista de espera do _Read-Ahead_.

```C
void
cache_read (block_sector_t sector, void *buffer)
{
    lock_acquire(&cache_lock);
    
    int index = cache_get_index(sector); // cache_get_index como função auxiliar para salvar aquele setor na cache
    struct cache_entry *entry = &cache[index];

    if (!entry->valid || entry->sector != sector) { // se não estiver mapeado, busca no disco
        block_read(fs_device, sector, entry->data);
        entry->valid = true;
        entry->sector = sector;
        entry->dirty = false;
    }
    
    
    if (buffer != NULL) { // se for uma leitura que necessita dos dados AGORA, copia-os para o buffer.
        memcpy(buffer, entry->data, BLOCK_SECTOR_SIZE);
    }

    entry->accessed = true;
    lock_release(&cache_lock);

    if (buffer != NULL && sector + 1 < block_size(fs_device)) { // Caso buffer != NULL e ainda haja espaço de disco, chama o read_ahead
        cache_trigger_read_ahead(sector + 1);
    }
}
```
 
- `cache_write(block_sector_t sector, const void *buffer)`: Escreve dados que estão no _buffer_ em determinado setor do disco.

```C
void
cache_write (block_sector_t sector, const void *buffer)
{
    lock_acquire(&cache_lock);
    
    int index = cache_get_index(sector); // Busca uma entrada da cache não utilizada recentemente
    struct cache_entry *entry = &cache[index];

    if (!entry->valid || entry->sector != sector) {
        entry->valid = true;
        entry->sector = sector;
    }
 
    memcpy(entry->data, buffer, BLOCK_SECTOR_SIZE); // copia do buffer para o data da entrada da cache
    entry->dirty = true; // coloca como sujo, caso seja expulso da cache
    entry->accessed = true;

    lock_release(&cache_lock);
}
```

- `cache_flush()`: Percorre todo o cache e salva as entradas sujas no disco.

```C
void
cache_flush (void)
{
    lock_acquire(&cache_lock);
    
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].dirty) {
            block_write(fs_device, cache[i].sector, cache[i].data);
            cache[i].dirty = false;
        }
    }

    lock_release(&cache_lock);
}
```

- `cache_write_behind_thread (void *aux UNUSED)`: É a função que será passada para a _thread_ que implementa o _Write-Behind_. Basicamente, de tempos em tempos, ela chamada o `cache_flush()` para salvar todas as entradas da _cache_ que foram alteradas.

```C
static void
cache_write_behind_thread (void *aux UNUSED)
{
  while (true) 
    {
      timer_sleep (5 * 100); 
      
      cache_flush(); 
    }
}
```

- `cache_read_ahead_thread (void *aux UNUSED)`: É a função passada para a _thread_ que implementa o _Read-Ahead_. Ela, quando escalonada, verifica se a lista de espera do _read-ahead_ não está vazia. Caso esteja, dorme. Para cada item nessa lista, será recuperado o setores posteriores dos arquivos e serão salvos em _cache_ ao passar o _buffer_ como nulo. 

```C
static void
cache_read_ahead_thread (void *aux UNUSED)
{
  while (true) 
    {
      lock_acquire (&read_ahead_lock);
      
      
      while (list_empty (&read_ahead_list)) 
        {
          cond_wait (&read_ahead_cond, &read_ahead_lock);
        }

      
      struct list_elem *e = list_pop_front (&read_ahead_list);
      struct read_ahead_entry *entry = list_entry (e, struct read_ahead_entry, elem);
      
      lock_release (&read_ahead_lock);
      cache_read(entry->sector, NULL); // Ao passar o buffer como nulo, apenas salva o setor no cache e não escreve nada no buffer.

      free (entry);
    }
}
```

- `cache_trigger_read_ahead (block_sector_t sector)`: É uma função que serve para guardar o próximo setor que pode ser chamado pelo processo na _read\_ahead\_list_ e acordar a _thread_ do _Read-Ahead_.

```C
void
cache_trigger_read_ahead (block_sector_t sector)
{
  
  struct read_ahead_entry *entry = malloc (sizeof (struct read_ahead_entry));
  if (entry == NULL) return;

  entry->sector = sector;

  lock_acquire (&read_ahead_lock);
  list_push_back (&read_ahead_list, &entry->elem);
  cond_signal (&read_ahead_cond, &read_ahead_lock); 
  lock_release (&read_ahead_lock);
}
```

### Outras partes do código alteradas:

Basicamente, alteramos a chamada de certas funções de baixo nível, substituindo `block_write()` e `block_read()` por, respectivamente, `cache_write()` e `cache_read()`. Todas as alterações foram centralizadas em `inode.c`.

```C
// Exemplo de alteração em inode.c

struct inode *
inode_open (block_sector_t sector)
{
  
  [...]

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (inode->sector, &inode->data); // chamada ao cache_read, onde antes estava o block_read.
  return inode;
}
```

## Conclusão:

É importante ressaltar que o grupo passou em *todos os testes*.




