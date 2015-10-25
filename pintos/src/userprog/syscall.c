#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

struct lock filesys_lock;

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
  //int argv = *((int *) f->esp);
  int argv = *(check_and_get_arg(f->esp, 0));//*((int *) f->esp);
//  uint32_t *addr;
//  addr  = (uint32_t *)f->esp + 1; /* calculate next argument address */

//printf("SYSTEM_CALL :: %d by %s\n", argv, thread_current()->name);

  switch (argv) {
    case SYS_HALT: {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      int status = *addr;
      sys_exit(status);
      break;
    }
    case SYS_EXEC: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      char *cmd_line = *addr;
      f->eax = sys_exec((const char *) cmd_line);
      break;
    }
    case SYS_WAIT: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      int pid = *addr;
      f->eax = sys_wait(pid);
      break;
    }
    case SYS_CREATE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      uint32_t* addr2 = check_and_get_arg(f->esp, 2);

      char *file = *addr;
      unsigned initial_size = *addr2;
      f->eax = sys_create((const char *) file, (unsigned) initial_size);
      break;
    }
    case SYS_REMOVE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      check_user_memory_access((void *) addr);

      char *file = *addr;
      f->eax = sys_remove((const char *) file);
      break;
    }
    case SYS_OPEN: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      check_user_memory_access((void *) addr);

      char *file = *addr;
      f->eax = sys_open((const char *) file);
      break;
    }
    case SYS_FILESIZE: {

      break;
    }
    case SYS_READ: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      uint32_t* addr2 = check_and_get_arg(f->esp, 2);
      uint32_t* addr3 = check_and_get_arg(f->esp, 3);

      int fd = *addr;
      void* buffer = *(addr2);
      unsigned size = *(addr3);

      f->eax = sys_read(fd, buffer, size);
      break;
    }
    case SYS_WRITE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      uint32_t* addr2 = check_and_get_arg(f->esp, 2);
      uint32_t* addr3 = check_and_get_arg(f->esp, 3);

      int fd = *addr;
      void* buffer = *(addr2);
      unsigned size = *(addr3);

      f->eax = sys_write(fd, buffer, size);
      break;
    }
    case SYS_SEEK: {

      break;
    }
    case SYS_TELL: {

      break;
    }
    case SYS_CLOSE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      int fd = *addr;
      sys_close(fd);
      break;
    }
  }
  /* 2015.10.05 Add for System call (e) */
}

void sys_exit(int status){
  /* 2015.10.20. Save status in PCB */
  thread_current()->my_process->status = status;

  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

tid_t sys_exec(char *cmd_line){
  check_user_memory_access(cmd_line);
  tid_t pid = process_execute(cmd_line);
  return pid;
}

int sys_wait(tid_t pid){
  int result = process_wait(pid); 
  return result;
}

int sys_read(int fd, void *buffer, unsigned size) {
  check_user_memory_access(buffer);
  if ( fd == 0 ) {
    int i = 0;
    for ( i = 0; i < size; i++) {
      //buffer[i] = input_getc();
    }
    return size;
  }
  lock_acquire(&filesys_lock);
  struct process_file *pf = get_file_by_fd (fd);
  if(pf == NULL){
    lock_release(&filesys_lock);
    return -1;
  }
  int result = file_read(pf->file, buffer, size);
  lock_release(&filesys_lock);
  return result;
  
}

int sys_write(int fd, const void *buffer, unsigned size) {
  check_user_memory_access(buffer);
  if ( fd == 1 ) {
    putbuf(buffer, size);
    return size;
  }

  lock_acquire(&filesys_lock);
  struct process_file *pf = get_file_by_fd (fd);
  if (pf == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  int result = file_write(pf->file, buffer, size);
  lock_release(&filesys_lock);
  return result;
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

int sys_open(const char *file){
  check_user_memory_access(file);
  if(!file || strlen(file) <= 0) {
    return -1;
  }

  lock_acquire(&filesys_lock);
  struct file *f= filesys_open(file);

  if (!f) {
    lock_release(&filesys_lock);
    return -1;
  }

  int fd = 0;
  struct process *p = thread_current()->my_process;
  fd = p->fd;
  struct process_file *pf = malloc(sizeof(struct process_file));
  pf->fd = fd;
  pf->file = f;
  list_push_back(&p->file_list, &pf->elem);
  p->fd++;  
  lock_release(&filesys_lock);
  return fd;
}

void sys_seek(int df, unsigned position){
  lock_acquire(&filesys_lock);
  //file_seek(fd, position);
  lock_release(&filesys_lock);
}

void sys_close(int fd){
  lock_acquire(&filesys_lock);
  struct process_file *pf = get_file_by_fd(fd);
  if (pf == NULL) {
    lock_release(&filesys_lock);
    return;
  }

  file_close(pf->file);
  list_remove(&pf->elem);
  free(pf);
  //file_seek(fd, position);
  lock_release(&filesys_lock);
}

/* 2015.10.14. User Memory Access (s) */
int* check_and_get_arg (void* addr, int pos){
  uint32_t *result;
  result = (uint32_t *) (addr + pos * 4);
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

/* 2015.10.22. Find file in the process by fd */
struct process_file* get_file_by_fd(int fd){
  struct thread *cur = thread_current ();
  struct process *p = cur->my_process;

  struct list_elem *e;
  for (e = list_begin (&p->file_list); e != list_end (&p->file_list); e = list_next (e)){
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (fd == pf->fd) {
      return pf;
    }
  }

  return NULL;
}
