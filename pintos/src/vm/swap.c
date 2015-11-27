#include "vm/swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "threads/vaddr.h"

void
swap_init(void) {
  swap_block = block_get_role (BLOCK_SWAP);
  if (!swap_block) {
    printf("CAN NOT GENERATE SWAP\n");
    return;
  }
  swap_map = bitmap_create (block_size(swap_block) * BLOCK_SECTOR_SIZE / PGSIZE);
  bitmap_set_all(swap_map, 0);
  lock_init(&swap_lock);
}
