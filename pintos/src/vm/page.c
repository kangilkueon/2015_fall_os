#include "vm/page.h"
#include <hash.h>
#include "lib/kernel/hash.h"


void spt_init () {
  hash_init(&s_page_table_hash, s_page_table_hash_func, s_page_table_hash_less, NULL);
}

struct s_page_table* s_page_table_init (void* addr) {
  struct s_page_table *spt = (struct s_page_table *) malloc(sizeof(struct s_page_table));
  spt->addr = addr;

  return spt;
}

unsigned
s_page_table_hash_func (const struct hash_elem *p_, void *aux)
{
  const struct s_page_table *t = hash_entry (p_, struct s_page_table, hash_elem);
  return hash_bytes (&t->addr, sizeof t->addr);
}

bool
s_page_table_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux)
{
  const struct s_page_table *a = hash_entry (a_, struct s_page_table, hash_elem);
  const struct s_page_table *b = hash_entry (b_, struct s_page_table, hash_elem);
  return a->vaddr < b->vaddr;
}

