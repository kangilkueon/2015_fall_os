#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <hash.h>
#include "lib/kernel/hash.h"
#include "threads/palloc.h"


void frame_init (void);
void* palloc_get_page_with_frame (enum palloc_flags flag, void* uaddr);
void palloc_free_page_with_frame(void *addr);
unsigned frame_hash_func (const struct hash_elem *p_, void *aux);
bool frame_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);

struct hash frame_hash;
struct lock frame_lock;

struct frame_table {
  void* uaddr;
  void* kaddr;
  struct hash_elem hash_elem;
};

void* get_victim_page (void);
#endif
