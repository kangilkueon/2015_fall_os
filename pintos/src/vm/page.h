#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "lib/kernel/hash.h"
#include "filesys/file.h"

enum s_page_status {
  S_PAGE_NORMAL,
  S_PAGE_SWAP
};

void spt_init (struct hash *spt);

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

  int status;
  int swap_loc;
};

bool create_s_page(void *page, struct file *file, size_t offset, size_t page_read_bytes, size_t page_zero_bytes, bool writable);
bool load_segment_by_s_page (void *addr);
void clear_s_page (void *page);

struct s_page* get_s_page (void *addr);
bool update_s_page_swap (void *addr, size_t swap_loc);

#endif
