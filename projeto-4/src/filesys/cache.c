#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include <string.h>

#define CACHE_SIZE 64





struct cache_entry {
    block_sector_t sector;  // Qual setor do disco está aqui?
    bool valid;             // Esta entrada está em uso?
    bool dirty;             // O conteúdo foi modificado e precisa ser salvo?
    bool accessed;          // Usado para o algoritmo do relógio (Clock/LRU)
    uint8_t data[BLOCK_SECTOR_SIZE]; // Os 512 bytes de dados
    struct lock entry_lock; // Opcional: Para sincronização fina (readers/writers)
};

static struct cache_entry cache[CACHE_SIZE];
static struct lock cache_lock; // Protege a lista do cache (busca/alocação)
static struct list read_ahead_list; /* Fila de setores a ler */
static struct lock read_ahead_lock; /* Protege a lista */
static struct condition read_ahead_cond; /* Avisa a thread que tem trabalho */

struct read_ahead_entry {
    block_sector_t sector;
    struct list_elem elem;
};


static void cache_write_behind_thread (void *aux UNUSED);
static void cache_read_ahead_thread (void *aux UNUSED);
void cache_trigger_read_ahead (block_sector_t sector);



void
cache_init (void) {
    lock_init(&cache_lock);
    for (int i = 0; i < CACHE_SIZE; i++) {
        cache[i].valid = false;
        lock_init(&cache[i].entry_lock);
    }
    list_init(&read_ahead_list);
    lock_init(&read_ahead_lock);
    cond_init(&read_ahead_cond);
    
    thread_create("cache_wb", PRI_DEFAULT, cache_write_behind_thread, NULL);
    thread_create("cache_ra", PRI_DEFAULT, cache_read_ahead_thread, NULL);
}

/* Algoritmo do Relógio (Clock Algorithm) para expulsão */
static int clock_hand = 0;

static int
cache_get_index (block_sector_t sector)
{
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].sector == sector) {
            cache[i].accessed = true; 
            return i;
        }
    }

    while (true) {
        if (!cache[clock_hand].valid) {
            return clock_hand;
        }

        if (cache[clock_hand].accessed) {
            cache[clock_hand].accessed = false;
        } else {
            if (cache[clock_hand].dirty) {
                block_write(fs_device, cache[clock_hand].sector, cache[clock_hand].data);
            }
            return clock_hand;
        }
        clock_hand = (clock_hand + 1) % CACHE_SIZE;
    }
}

void
cache_read (block_sector_t sector, void *buffer)
{
    lock_acquire(&cache_lock);
    
    int index = cache_get_index(sector);
    struct cache_entry *entry = &cache[index];

    /* Se acabamos de alocar este slot para um setor novo, carregamos do disco */
    if (!entry->valid || entry->sector != sector) {
        block_read(fs_device, sector, entry->data);
        entry->valid = true;
        entry->sector = sector;
        entry->dirty = false;
    }
    
    /* Copia do cache para o buffer do usuário */
    if (buffer != NULL) {
        memcpy(buffer, entry->data, BLOCK_SECTOR_SIZE);
    }

    entry->accessed = true;
    lock_release(&cache_lock);

    /* --- CORREÇÃO AQUI --- */
    /* Só dispara o Read-Ahead se for uma leitura REAL (buffer != NULL).
       Isso evita que a thread de Read-Ahead entre em loop infinito lendo o disco todo. */
    if (buffer != NULL && sector + 1 < block_size(fs_device)) {
        cache_trigger_read_ahead(sector + 1);
    }
}

void
cache_write (block_sector_t sector, const void *buffer)
{
    lock_acquire(&cache_lock);
    
    int index = cache_get_index(sector);
    struct cache_entry *entry = &cache[index];

    /* Mesmo para escrita, precisamos carregar o bloco se ele não estiver lá
       (Write-Back Policy) */
    if (!entry->valid || entry->sector != sector) {
        /* Otimização: Se formos sobrescrever TUDO, não precisa ler do disco antes. 
           Mas para simplificar, leia sempre. */
        block_read(fs_device, sector, entry->data);
        entry->valid = true;
        entry->sector = sector;
    }

    /* Copia do buffer do usuário para o cache */
    memcpy(entry->data, buffer, BLOCK_SECTOR_SIZE);
    entry->dirty = true; /* MARCA COMO SUJO! Só grava no disco na expulsão ou flush */
    entry->accessed = true;

    lock_release(&cache_lock);
}

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

static void
cache_write_behind_thread (void *aux UNUSED)
{
  while (true) 
    {
      /* Dorme por 5 segundos (assumindo TIMER_FREQ = 100) */
      timer_sleep (5 * 100); 
      
      /* Salva os blocos sujos no disco */
      cache_flush(); 
    }
}

static void
cache_read_ahead_thread (void *aux UNUSED)
{
  while (true) 
    {
      lock_acquire (&read_ahead_lock);
      
      /* Se a lista estiver vazia, dorme e espera sinal */
      while (list_empty (&read_ahead_list)) 
        {
          cond_wait (&read_ahead_cond, &read_ahead_lock);
        }

      /* Pega o primeiro item da fila */
      struct list_elem *e = list_pop_front (&read_ahead_list);
      struct read_ahead_entry *entry = list_entry (e, struct read_ahead_entry, elem);
      
      lock_release (&read_ahead_lock);

      cache_read(entry->sector, NULL);

      /* Limpeza */
      free (entry);
    }
}


void
cache_trigger_read_ahead (block_sector_t sector)
{
  /* Aloca a entrada */
  struct read_ahead_entry *entry = malloc (sizeof (struct read_ahead_entry));
  if (entry == NULL) return;

  entry->sector = sector;

  lock_acquire (&read_ahead_lock);
  list_push_back (&read_ahead_list, &entry->elem);
  cond_signal (&read_ahead_cond, &read_ahead_lock); /* Acorda o worker */
  lock_release (&read_ahead_lock);
}


