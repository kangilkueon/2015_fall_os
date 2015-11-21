#include "vm/frame.h"
#include <hash.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"

void frame_init () {
  lock_init(&frame_lock);
  hash_init(&frame_hash, frame_hash_func, frame_hash_less, NULL);
}

void *
palloc_get_page_with_frame (enum palloc_flags flags)
{
  uint8_t* kpage = palloc_get_multiple (flags, 1);
  
  if (kpage == NULL) {
    return false;
  }
  lock_acquire(&frame_lock);
  struct frame_table *ft = (struct frame_table *) malloc(sizeof(struct frame_table));
  ft->page = kpage;

  hash_insert(&frame_hash, &ft->hash_elem);
  lock_release(&frame_lock);
  return kpage;
}

void
palloc_free_page_with_frame (void *addr)
{
  struct frame_table *ft = (struct frame_table *) malloc(sizeof(struct frame_table));
  ft->page = addr;

  struct hash_elem *he = hash_find (&frame_hash, &ft->hash_elem);
  free (ft);
  ft = hash_entry (he, struct frame_table, hash_elem);

  lock_acquire(&frame_lock);
  hash_delete(&frame_hash, &ft->hash_elem);
  lock_release(&frame_lock);
  
  palloc_free_page(addr);
}

unsigned
frame_hash_func (const struct hash_elem *p_, void *aux)
{
  const struct frame_table *t = hash_entry (p_, struct frame_table, hash_elem);
  return hash_bytes (&t->page, sizeof t->page);
}

bool
frame_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux)
{
  const struct frame_table *a = hash_entry (a_, struct frame_table, hash_elem);
  const struct frame_table *b = hash_entry (b_, struct frame_table, hash_elem);
  return a->page < b->page;
}
