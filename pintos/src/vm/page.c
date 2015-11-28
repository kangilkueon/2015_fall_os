#include "vm/page.h"
#include <hash.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "lib/kernel/hash.h"


void spt_init (struct hash *spt) {
  hash_init(spt, s_page_table_hash_func, s_page_table_hash_less, NULL);
}

unsigned
s_page_table_hash_func (const struct hash_elem *p_, void *aux)
{
  const struct s_page *sp = hash_entry (p_, struct s_page, hash_elem);
  return hash_bytes (&sp->page, sizeof sp->page);
}

bool
s_page_table_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux)
{
  const struct s_page *a = hash_entry (a_, struct s_page, hash_elem);
  const struct s_page *b = hash_entry (b_, struct s_page, hash_elem);
  return a->page < b->page;
}

bool create_s_page(void *page, struct file *file, size_t offset, size_t page_read_bytes, size_t page_zero_bytes, bool writable) {
  struct s_page *sp = (struct s_page *) malloc (sizeof(struct s_page));
  if (sp == NULL) {
    return false;
  }

  sp->page = page;
  sp->file = file;
  sp->offset = offset;
  sp->page_read_bytes = page_read_bytes;
  sp->page_zero_bytes = page_zero_bytes;
  sp->writable = writable;
  sp->is_load = false;
  sp->status = S_PAGE_NORMAL;

  struct thread *curr = thread_current();

  if (hash_insert(&curr->my_process->spt, &sp->hash_elem) != NULL) {
    return false;
  }

  return true;
}

bool load_segment_by_s_page (void* addr) {
  /* Get page from page table */
  uint8_t *kpage = palloc_get_page_with_frame(PAL_USER, addr);
  struct s_page *sp = get_s_page (addr);
  if (sp == NULL) {
    free(sp);
    return false;
  }

  /* Get a page of memory. */
  if (kpage == NULL) {
    free(sp);
    return false;
  }

  /* 2015.11.28. Implement swap */
  if (sp->status == S_PAGE_SWAP) {
    swap_read (kpage, sp->swap_loc);
    sp->status = S_PAGE_NORMAL;
  } else {
    lock_acquire(&filesys_lock);

    /* Load this page. */
    file_seek(sp->file, sp->offset);
    if (file_read (sp->file, kpage, sp->page_read_bytes) != (int) sp->page_read_bytes) {
      palloc_free_page_with_frame (kpage);
      free(sp);
      lock_release(&filesys_lock);
      return false; 
    }
    memset (kpage + sp->page_read_bytes, 0, sp->page_zero_bytes);

    lock_release(&filesys_lock);
  }

  /* Add the page to the process's address space. */
  if (!install_page (sp->page, kpage, sp->writable)) {
    palloc_free_page_with_frame (kpage);
    free(sp);
    return false; 
  }
  sp->is_load = true;
  return true;
}

void clear_s_page (void* page) {
  struct s_page *sp = get_s_page (page);
  if (sp == NULL) {
    return;
  }
  if (sp->is_load) 
  if(pagedir_is_dirty(thread_current()->pagedir, sp->page)) {
    file_write_at (sp->file, sp->page, PGSIZE, 0);
  }
  palloc_free_page_with_frame (pagedir_get_page (thread_current ()->pagedir, sp->page));
  pagedir_clear_page (thread_current ()->pagedir, sp->page);
  hash_delete (&thread_current ()->my_process->spt, &sp->hash_elem);
  free (sp);
}

struct s_page* get_s_page(void *addr) {
  struct s_page *sp = (struct s_page *) malloc(sizeof(struct s_page));
  sp->page = addr;
  struct hash_elem *e = hash_find(&thread_current()->my_process->spt, &sp->hash_elem);
  if (e == NULL) {
    return NULL;
  }
  free(sp);
  sp = hash_entry (e, struct s_page, hash_elem);
  return sp;
}

bool update_s_page_swap (void *addr, size_t swap_loc) {
  struct s_page *sp = get_s_page (addr);
  if (sp == NULL) {
printf("what is your addr %x\n", addr);
printf("sp null?\n");
    return false;
  }
  sp->status = S_PAGE_SWAP;
  sp->swap_loc = swap_loc;
  return true;
}
