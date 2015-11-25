#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

void sys_exit(int status);
tid_t sys_exec(char *cmd_line);
int sys_create(const char *file, unsigned initial_size);
int sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_mmap (int fd, void *addr);
void sys_munmap (int mapping);


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
  int argv = *(check_and_get_arg(f->esp, 0));

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
      char *cmd_line = (char *) *addr;
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

      char *file = (char *) *addr;
      f->eax = sys_remove((const char *) file);
      break;
    }
    case SYS_OPEN: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      check_user_memory_access((void *) addr);

      char *file = (char *) *addr;
      f->eax = sys_open((const char *) file);
      break;
    }
    case SYS_FILESIZE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      check_user_memory_access((void *) addr);

      int fd = *addr;
      f->eax = sys_filesize(fd);
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
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      uint32_t* addr2 = check_and_get_arg(f->esp, 2);

      int fd = *addr;
      unsigned position = *(addr2);

      sys_seek(fd, position);
      break;
    }
    case SYS_TELL: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);

      int fd = *addr;
      f->eax = sys_tell(fd);
      break;
    }
    case SYS_CLOSE: {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      int fd = *addr;
      sys_close(fd);
      break;
    }
    case SYS_MMAP : {
      uint32_t *addr = check_and_get_arg(f->esp, 1);
      uint32_t* addr2 = check_and_get_arg(f->esp, 2);

      int fd = *addr;
      void* t_addr = *(addr2);

      f->eax = sys_mmap (fd, t_addr);
      break;
    }
    case SYS_MUNMAP : {
      uint32_t *addr = check_and_get_arg(f->esp, 1);

      int mapping = *addr;

      sys_munmap (mapping);
      break;
    }
  }
  /* 2015.10.05 Add for System call (e) */
}

void sys_exit(int status){
  /* 2015.10.26. Close all file */
  close_all_file(thread_current()->my_process);

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
  check_user_memory_access(file);
  if(!file || strlen(file) <= 0){
    sys_exit (-1);
  }

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
  lock_release(&filesys_lock);

  if (!f) {
    return -1;
  }

  int fd = 0;
  struct process *p = thread_current()->my_process;
  fd = p->fd;
  struct process_file *pf = (struct process_file *) malloc(sizeof(struct process_file));
  if(pf == NULL) {
    return -1;
  }
  pf->fd = fd;
  pf->file = f;
  list_push_back(&p->file_list, &pf->elem);
  p->fd++;  
  return fd;
}

int sys_filesize(int fd){
  struct process_file *pf = get_file_by_fd (fd);

  if(pf == NULL){
    return -1;
  }
  lock_acquire(&filesys_lock);
  int result = file_length(pf->file);
  lock_release(&filesys_lock);

  return result;
}

int sys_read(int fd, void *buffer, unsigned size) {
  check_user_memory_access(buffer);
  if ( fd == 0 ) {
    unsigned i = 0;
    for ( i = 0; i < size; i++) {
      *(uint8_t *)(buffer + i) = input_getc();
    }
    return size;
  }
  struct process_file *pf = get_file_by_fd (fd);
  if(pf == NULL){
    return -1;
  }
  lock_acquire(&filesys_lock);
//TODO printf("Error occrue here\n")
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

  struct process_file *pf = get_file_by_fd (fd);
  if (pf == NULL) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  int result = file_write(pf->file, buffer, size);
  lock_release(&filesys_lock);

  return result;
}

void sys_seek(int fd, unsigned position){
  struct process_file *pf = get_file_by_fd (fd);
  if(pf == NULL){
    return;
  }

  lock_acquire(&filesys_lock);
  file_seek(pf->file, position);
  lock_release(&filesys_lock);
}

unsigned sys_tell(int fd){
  unsigned result;
  struct process_file *pf = get_file_by_fd (fd);
  if(pf == NULL){
    return -1;
  }
  lock_acquire(&filesys_lock);
  result = file_tell(pf->file);
  lock_release(&filesys_lock);

  return result;
}

void sys_close(int fd){
  struct process_file *pf = get_file_by_fd(fd);
  if (pf == NULL) {
    return;
  }

  lock_acquire(&filesys_lock);
  file_close(pf->file);
  list_remove(&pf->elem);
  free(pf);

  lock_release(&filesys_lock);
}

/* 2015.11.25. Memeory Mapped File */
int sys_mmap (int fd, void *addr) {
  /* Handling error data */
  if (fd == 0 || fd == 1) {
    return -1;
  }

  if (!addr || ((uint32_t) addr & PGSIZE) != 0) {
    return -1;
  }

  struct process_file *pf = get_file_by_fd (fd);
  if (pf == NULL) {
    return -1;
  }
  
  size_t read_bytes = file_length (pf->file);
  if (read_bytes <= 0) {
    return -1;
  }

  struct process *p = thread_current ()->my_process;
  int map_id = p->map_id;

  lock_acquire(&filesys_lock);
  /* Start logic */
  size_t ofs = 0;
  while (read_bytes > 0) {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* 2015.11.24. Implement on-demand loading */
      bool success = create_s_page(addr, pf->file, ofs, page_read_bytes, page_zero_bytes, true);
      if (!success) {
        printf("fail to allocate supplemental page\n");
      }

      /* Advance. */
      read_bytes -= page_read_bytes;
      ofs += page_read_bytes;
  }

  struct mmap_file *mf = (struct mmap_file *) malloc(sizeof(struct mmap_file));
  mf->map_id = map_id;
  list_push_back(&p->mmap_list, &mf->elem);
  p->map_id = map_id + 1;
  lock_release(&filesys_lock);
  return map_id;
}

void sys_munmap (int mapping) {

}

/* 2015.10.14. User Memory Access (s) */
unsigned* check_and_get_arg (void* addr, int pos){
  unsigned *result;
  result = (uint32_t *) (addr + pos * 4);
  check_user_memory_access((void *) result);

  return result;
}

void check_user_memory_access(void* addr){
  if(addr == NULL || !is_user_vaddr(addr)){
    sys_exit(-1);
  } else {
    void *page = (void *) pagedir_get_page(thread_current()->pagedir, addr);

    if(!page) {
      sys_exit(-1);
    }
  }
  return;
}
/* 2015.10.14. User Memory Access (e) */

