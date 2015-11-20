#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/file.h"
#include "threads/thread.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* 2015.10.13 Process structure (s) */
struct process {
  tid_t pid;
  int status;

  /* 2015.10.25. Implement load-failed process */
  int load;
  int fd;
  struct file *exec_file;
  struct thread *my_thread;
  struct semaphore exec_sema; 
  struct semaphore exit_sema; 
  //struct semaphore status_sema;
  struct list file_list;

  /* 2015.10.27. To preserve PCB when thread destroy */
  struct list_elem child_elem;
  int exit;
};

/* 2015.10.22. To File System */
struct process_file {
  int fd;
  struct file *file;
  struct list_elem elem;
};

struct lock filesys_lock;

struct process* get_process_by_tid (tid_t tid);
struct process_file* get_file_by_fd(int fd);
void close_all_file (struct process *p);


/* 2015.10.13 Process structure (e) */

#endif /* userprog/process.h */
