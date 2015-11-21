#include <hash.h>
#include "lib/kernel/hash.h"

struct hash s_page_table_hash;

void spt_init (void);
struct s_page_table* s_page_table_init (void *);

unsigned s_page_table_hash_func (const struct hash_elem *p_, void *aux);
bool s_page_table_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);

struct s_page_table {
  void* addr;
  void* vaddr;
  struct hash_elem hash_elem;
};

