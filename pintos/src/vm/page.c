#include "vm/page.h"

void spt_init () {

}

void s_page_table_init (void* addr) {
  struct s_page_table *spt = (struct s_page_table*) malloc(sizeof(struct s_page_table));
  spt->addr = addr;
}

