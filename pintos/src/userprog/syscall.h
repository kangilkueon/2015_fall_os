#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

unsigned* check_and_get_arg (void *addr, int pos);
void check_user_memory_access(void* addr);
void munmap_all (void);
#endif /* userprog/syscall.h */
