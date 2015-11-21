#include <hash.h>

struct hash s_page_table_hash;
struct s_page_table {
  void* addr;
  struct hash_elem elem;
};

void spt_init (void);
void s_page_table_init (void *);
