#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

filesys_lock;

static void syscall_handler (struct intr_frame *);
tid_t sys_exec(char *cmd_line);

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* 2015.10.14. Implement user memory access */ 
  check_user_memory_access(f->esp);

  /* 2015.10.05. Add for System call (s) */
  int argv = *((int *) f->esp);
//  uint32_t *addr;
//  addr  = (uint32_t *)f->esp + 1; /* calculate next argument address */

//printf("SYSTEM_CALL :: %d\n", argv);

  switch (argv) {
    case SYS_HALT: {
      shutdown_power_off();
    }
    case SYS_EXIT: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      int status = *addr;
      sys_exit(status);
    }
    case SYS_EXEC: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      char *cmd_line = *addr;
      f->eax = sys_exec((const char *) cmd_line);
    }
    case SYS_WAIT: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      int pid = *addr;
      f->eax = sys_wait(pid);
    }
    case SYS_CREATE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      uint32_t* addr2 = check_and_get_arg(f->esp, 2);

      char *file = *addr;
      unsigned initial_size = *addr2;
      f->eax = sys_create((const char *) file, (unsigned) initial_size);
    }
    case SYS_REMOVE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      check_user_memory_access((void *) addr);

      char *file = addr;
      f->eax = sys_remove((const char *) file);
    }
    case SYS_OPEN: {

    }
    case SYS_FILESIZE: {

    }
    case SYS_READ: {

    }
    case SYS_WRITE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      uint32_t* addr2 = check_and_get_arg(f->esp, 2);
      uint32_t* addr3 = check_and_get_arg(f->esp, 3);

      int fd = *addr;
      void* buffer = *(addr2);
      unsigned size = *(addr3);

      f->eax = sys_write(fd, buffer, size);
    }
    case SYS_SEEK: {

    }
    case SYS_TELL: {

    }
    case SYS_CLOSE: {

    }
  }
  /* 2015.10.05 Add for System call (e) */
}

void sys_exit(int status){
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

tid_t sys_exec(char *cmd_line){
  tid_t pid = process_execute(cmd_line);
  
  return pid;
}

int sys_wait(tid_t pid){
  return process_wait(pid); 
}

int sys_write(int fd, const void *buffer, unsigned size) {
  if ( fd == 1 ) {
    putbuf(buffer, size);
  }
  return size; 
}

int sys_create(const char *file, unsigned initial_size){
  check_user_memory_access(file);
  if(!file || strlen(file) <= 0) {
    sys_exit (-1);
  }

  lock_acquire(&filesys_lock);
  int success = filesys_create(file, initial_size);

  lock_release(&filesys_lock);
  return success;
}

int sys_remove(const char *file) {
  lock_acquire(&filesys_lock);
  int success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

void sys_seek(int df, unsigned position){
  lock_acquire(&filesys_lock);
  //file_seek(fd, position);
  lock_release(&filesys_lock);
}
/* 2015.10.14. User Memory Access (s) */
int* check_and_get_arg (void* addr, int pos){
  uint32_t *result;
  result = (uint32_t *) addr + pos;
  check_user_memory_access((void *) result);

  return result;
}

void check_user_memory_access(void* addr){
  if(addr == NULL || !is_user_vaddr(addr)){
    sys_exit(-1);
  } else {
    void *page = pagedir_get_page(thread_current()->pagedir, addr);
    if(!page) sys_exit(-1);
  }
  return;
}
/* 2015.10.14. User Memory Access (e) */
