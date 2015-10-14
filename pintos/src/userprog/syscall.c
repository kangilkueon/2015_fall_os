#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
tid_t sys_exec(char *cmd_line);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* 2015.10.14. Implement user memory access */ 
  check_user_memory_access(f->esp);

  /* 2015.10.05. Add for System call (s) */
  int argv = *((int *) f->esp);
  uint32_t *addr;
  addr  = (uint32_t *)f->esp + 1; /* calculate next argument address */

//printf("SYSTEM_CALL :: %d\n", argv);

  switch (argv) {
    case SYS_HALT: {
      shutdown_power_off();
    }
    case SYS_EXIT: {
      check_user_memory_access((void *) addr);
      int status = *addr;
      sys_exit(status);
    }
    case SYS_EXEC: {
      check_user_memory_access((void *) addr);
      char *cmd_line = addr;
      f->eax = sys_exec(cmd_line);
    }
  }
  if(argv == SYS_WAIT){
    int pid = *addr;
    wait(pid); 
  } else if(argv == SYS_CREATE) {
    char *file = addr;
  } else if(argv == SYS_REMOVE) {

  } else if(argv == SYS_OPEN) {
  } else if(argv == SYS_FILESIZE) {
  } else if(argv == SYS_READ) {
  } else if(argv == SYS_WRITE) {
    int fd = *addr;
    void* buffer = *(addr + 1);
    unsigned size = *(addr + 2);

    f->eax = write(fd, buffer, size);
//    printf("fd :: %d\n", fd);
//    printf("buffer :: %d\n", buffer);
//    printf("size :: %d\n", size);
//    printf("what?\n");
  } else if(argv == SYS_SEEK) {
  } else if(argv == SYS_TELL) {


  } else if(argv == SYS_CLOSE) {

  }
  else printf ("system call!\n");
  /* 2015.10.05 Add for System call (e) */
  //thread_exit ();
}

void sys_exit(int status){
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

tid_t sys_exec(char *cmd_line){
  tid_t pid = process_execute(cmd_line);
  
  return pid;
}

int wait(tid_t pid){
  return process_wait(pid); 
}

int write(int fd, const void *buffer, unsigned size) {
  putbuf(buffer, size);
  return size; 
}



/* 2015.10.14. User Memory Access (s) */
void check_user_memory_access(void* addr){
  if(addr == NULL || !is_user_vaddr(addr) ){
    sys_exit(-1);
  } else {
    void *page = pagedir_get_page(thread_current()->pagedir, addr);
    if(!page) sys_exit(-1);
  }
  return;
}
/* 2015.10.14. User Memory Access (e) */
