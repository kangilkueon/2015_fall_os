#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

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
  int fd;
  struct thread *my_thread;
  struct semaphore wait_sema; 
  struct semaphore exit_sema; 
  struct list file_list;
  bool exit;
};

/* 2015.10.22. To File System */
struct process_file {
  int fd;
  struct file *file;
  struct list_elem elem;
};


struct process* get_process_by_tid (tid_t tid);
/* 2015.10.13 Process structure (e) */

#endif /* userprog/process.h */
