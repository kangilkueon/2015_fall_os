#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"

void swap_init(void);

struct block *swap_block;
struct bitmap *swap_map;
struct lock swap_lock;

size_t swap_write (void* addr);
void swap_read (void);
#endif
