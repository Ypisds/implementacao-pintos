#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include <string.h>

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



void
cache_init (void) {
    lock_init(&cache_lock);
    list_init(&read_ahead_list);
    lock_init(&read_ahead_lock);
    cond_init(&read_ahead_cond);
    
    thread_create("cache_wb", PRI_DEFAULT, cache_write_behind_thread, NULL);
    thread_create("cache_ra", PRI_DEFAULT, cache_read_ahead_thread, NULL);
}

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

    if (!entry->valid || entry->sector != sector) {
        block_read(fs_device, sector, entry->data);
        entry->valid = true;
        entry->sector = sector;
        entry->dirty = false;
    }
    
    
    if (buffer != NULL) {
        memcpy(buffer, entry->data, BLOCK_SECTOR_SIZE);
    }

    entry->accessed = true;
    lock_release(&cache_lock);

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

    
    if (!entry->valid || entry->sector != sector) {
        entry->valid = true;
        entry->sector = sector;
    }

    
    memcpy(entry->data, buffer, BLOCK_SECTOR_SIZE);
    entry->dirty = true;
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
      timer_sleep (5 * 100); 
      
      cache_flush(); 
    }
}

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
      cache_read(entry->sector, NULL);

      free (entry);
    }
}


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


