#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "lib/kernel/hash.h"
#include "filesys/file.h"

void spt_init (struct hash *spt);
struct s_page_table* s_page_table_init (void *);

unsigned s_page_table_hash_func (const struct hash_elem *p_, void *aux);
bool s_page_table_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);

struct s_page {
  struct hash_elem hash_elem;
  void* page;

  struct file *file;
  size_t offset;
  size_t page_read_bytes;
  size_t page_zero_bytes;

  bool writable;
  bool is_load;
};

bool create_s_page(void *page, struct file *file, size_t offset, size_t page_read_bytes, size_t page_zero_bytes, bool writable);
bool load_segment_by_s_page (void *addr);
void clear_s_page (void *page);

struct s_page* get_s_page (void *addr);

#endif
