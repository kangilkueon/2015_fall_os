#include "vm/swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "threads/vaddr.h"

void
swap_init(void) {
  swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL) {
    printf("##### CAN NOT GENERATE SWAP\n");
    return;
  }
  swap_map = bitmap_create (block_size(swap_block) * BLOCK_SECTOR_SIZE / PGSIZE);
  bitmap_set_all(swap_map, 0);
  lock_init(&swap_lock);
}

size_t swap_write (void* addr) {
  int end_size = PGSIZE / BLOCK_SECTOR_SIZE;
  lock_acquire(&swap_lock);
  size_t swap_loc  = bitmap_scan_and_flip(swap_map, 0, 1, 0);

  if (swap_loc == BITMAP_ERROR) {
    lock_release(&swap_lock);
    return 0;
  }
  int i;
  for (i = 0; i < end_size; i++) { 
    block_write(swap_block, swap_loc * end_size + i, (uint8_t *) addr + i * BLOCK_SECTOR_SIZE);
  }
  lock_release(&swap_lock);
  return swap_loc;
}

void swap_read (void *kpage, size_t swap_loc) {
  int end_size = PGSIZE / BLOCK_SECTOR_SIZE;
  lock_acquire(&swap_lock);
  if (bitmap_test(swap_map, swap_loc) == 0) {
    lock_release(&swap_lock);
    return;
  }
  bitmap_flip(swap_map, swap_loc);
  int i;
  for (i = 0; i < end_size; i++) {
    block_read(swap_block, swap_loc * end_size + i, (uint8_t *) kpage + i * BLOCK_SECTOR_SIZE);
  } 
  lock_release(&swap_lock);
}
