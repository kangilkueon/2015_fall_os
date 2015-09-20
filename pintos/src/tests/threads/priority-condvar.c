/* Tests that cond_signal() wakes up the highest-priority thread
   waiting in cond_wait(). */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

static thread_func priority_condvar_thread;
static struct lock lock;
static struct condition condition;

void
test_priority_condvar (void) 
{
  int i;
  
  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  lock_init (&lock);
  cond_init (&condition);

  thread_set_priority (PRI_MIN);
  for (i = 0; i < 10; i++) 
    {
      int priority = PRI_DEFAULT - (i + 7) % 10 - 1;
      char name[16];
      snprintf (name, sizeof name, "priority %d", priority);
      thread_create (name, priority, priority_condvar_thread, NULL);
    }

//msg("[0] Lock Holder :: %d (priority : %d)", lock.holder->tid, lock.holder->priority);
  for (i = 0; i < 10; i++) 
    {
      lock_acquire (&lock);
      msg ("Signaling...");
//msg("[1] Lock Holder :: %d (priority : %d, %d)", lock.holder->tid, lock.holder->priority, lock.holder->d_priority);
//msg("[1-1] Lock Holder :: %d (priority : %d, %d)", list_size(&lock.holder->donors), lock.holder->priority, lock.holder->d_priority);
      cond_signal (&condition, &lock);
//msg("[3] Lock Holder :: %d (priority : %d, %d)", lock.holder->tid, lock.holder->priority, lock.holder->d_priority);
      lock_release (&lock);
    }
//msg("[4] priority : %d, %d", thread_current()->priority, thread_current()->d_priority);
}

static void
priority_condvar_thread (void *aux UNUSED) 
{
  msg ("Thread %s starting.", thread_name ());
  lock_acquire (&lock);
//msg("[2] Lock Holder :: %d (priority : %d, %d)", lock.holder->tid, lock.holder->priority, lock.holder->d_priority);
  cond_wait (&condition, &lock);
  msg ("Thread %s woke up.", thread_name ());
  lock_release (&lock);
}
