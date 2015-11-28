#include "vm/frame.h"
#include <hash.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

void frame_init () {
  lock_init(&frame_lock);
  hash_init(&frame_hash, frame_hash_func, frame_hash_less, NULL);
}

void *
palloc_get_page_with_frame (enum palloc_flags flags, void* uaddr)
{
  uint8_t* kpage = palloc_get_page (flags);
  
  /* 2015.11.28. Implement Swap */
  while (kpage == NULL) {
    lock_acquire (&frame_lock);
    void *victim = get_victim_page (); /* Kernel address */
    void *victim_uaddr = get_uaddr_from_kaddr(victim);
    if (!update_s_page_swap (victim_uaddr, swap_write (victim))){
      printf("Palloc in swap error\n");
      lock_release (&frame_lock);
      return NULL;
    }
    pagedir_clear_page (thread_current ()->pagedir, victim_uaddr);
    lock_release (&frame_lock);
    palloc_free_page_with_frame (victim);
    kpage = palloc_get_page (flags);
  }

  lock_acquire(&frame_lock);
  struct frame_table *ft = (struct frame_table *) malloc(sizeof(struct frame_table));
  ft->kaddr = kpage;
  ft->uaddr = uaddr;

  hash_insert(&frame_hash, &ft->hash_elem);
  lock_release(&frame_lock);
  return kpage;
}

void
palloc_free_page_with_frame (void *addr)
{
  struct frame_table *ft = (struct frame_table *) malloc(sizeof(struct frame_table));
  ft->kaddr = addr;

  palloc_free_page(addr);

  struct hash_elem *he = hash_find (&frame_hash, &ft->hash_elem);
  free (ft);
  if (he == NULL) {
    return;
  }
  ft = hash_entry (he, struct frame_table, hash_elem);

  lock_acquire(&frame_lock);
  hash_delete(&frame_hash, &ft->hash_elem);
  lock_release(&frame_lock);
}

/* 2015.11.28. Get victim page */
void *
get_victim_page (void) {
  void* victim = NULL;
  struct hash_iterator i;
  hash_first(&i, &frame_hash);
  struct hash_elem *he = hash_cur (&i);
  struct frame_table *ft = hash_entry (he, struct frame_table, hash_elem);
  size_t size = hash_size (&frame_hash);
  size_t idx;
  for (idx = 0; idx < size; idx++) {
    he = hash_next (&i);
    ft = hash_entry (he, struct frame_table, hash_elem);
    if (pagedir_is_accessed (thread_current()->pagedir, ft->uaddr)) {
      pagedir_set_accessed (thread_current()->pagedir, ft->uaddr, false);
    } else {
      victim = ft->kaddr;
      return victim; 
    }
  }
  victim = ft->kaddr;
  return victim; 
}

unsigned
frame_hash_func (const struct hash_elem *p_, void *aux)
{
  const struct frame_table *t = hash_entry (p_, struct frame_table, hash_elem);
  return hash_bytes (&t->kaddr, sizeof t->kaddr);
}

bool
frame_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux)
{
  const struct frame_table *a = hash_entry (a_, struct frame_table, hash_elem);
  const struct frame_table *b = hash_entry (b_, struct frame_table, hash_elem);
  return a->kaddr < b->kaddr;
}

void *
get_uaddr_from_kaddr (void *kaddr) {
  struct frame_table *ft = (struct frame_table *) malloc(sizeof(struct frame_table));
  ft->kaddr = kaddr;

  struct hash_elem *he = hash_find (&frame_hash, &ft->hash_elem);
  free (ft);
  if (he == NULL) {
    return NULL;
  }
  ft = hash_entry (he, struct frame_table, hash_elem);
  return (uint32_t *) ft->uaddr;
}
