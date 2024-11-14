/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * logfs.c
 */

#include <pthread.h>
#include "device.h"
#include "logfs.h"

#define WCACHE_BLOCKS 32
#define RCACHE_BLOCKS 256

struct logfs
{
  void *writebuffer;          /* Buffer to write to, aligned */
  void *writebuffer_toDelete; /* Buffer to write to, unaligned to delete on close */

  size_t BUFFER_SIZE; /* The buffer size. A constant */
  size_t BLOCK_SIZE;  /* The block size. A constant */
  size_t head;        /* The offset on the buffer to write to */
  size_t tail;        /* The offset on the buffer to read from (for writing to disk) */

  pthread_t writer;           /* Our worker thread for writing */
  pthread_mutex_t lock;       /* A mutex to lock down our threadwork */
  pthread_cond_t data_avail;  /* Flag to mark if we have data available (if we can write more to disk) */
  pthread_cond_t space_avail; /* Flag to mark if we have space available (if we can write more to buffer) */

  size_t CAPACITY; /* Constant to store block device's capacity */

  int done; /* If we are done. For closing up threadwork */
};

size_t size(struct logfs *logfs)
{
  return (logfs->head - logfs->tail) % WCACHE_BLOCKS;
}

void *writer(struct logfs *logfs)
{
  pthread_mutex_lock(&logfs->lock);
  while (!logfs->done)
  {
    if (size(logfs) < logfs->BLOCK_SIZE)
    {
      /* TODO: Can we flush here? SHOULD we flush here? */
      pthread_cond_wait(&logfs->data_avail, &logfs->lock);
      continue;
    }

    device_write(/* TODO: How do we get the device? */ NULL, shift(logfs->writebuffer, (logfs->tail % logfs->BUFFER_SIZE)), logfs->tail, logfs->BLOCK_SIZE);
    logfs->tail += logfs->BLOCK_SIZE;

    pthread_cond_signal(&logfs->space_avail);
  }

  pthread_mutex_unlock(&logfs->lock);

  return NULL;
}

struct logfs *logfs_open(const char *pathname)
{
  /* STUB! */
  UNUSED(pathname);
  return NULL;
}

void logfs_close(struct logfs *logfs)
{
  /* STUB! */
  UNUSED(logfs);
}

int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len)
{
  /* STUB! */

  UNUSED(logfs);
  UNUSED(buf);
  UNUSED(off);
  UNUSED(len);

  return 0;
}

int logfs_append(struct logfs *logfs, const void *buf, uint64_t len)
{
  if (logfs->head + len > logfs->CAPACITY)
  {
    /* Error! No capacity */
  }

  assert(len <= logfs->BUFFER_SIZE);
  for (;;)
  {
    if ((logfs->BUFFER_SIZE - size(logfs)) < len)
    {
      pthread_cond_wait(&logfs->space_avail, &logfs->lock);
      continue;
    }
    break;
  }

  if ((logfs->head % logfs->BUFFER_SIZE) + len > logfs->BUFFER_SIZE)
  {
    memcpy(shift(logfs->writebuffer, (logfs->head % logfs->BUFFER_SIZE)), buf, logfs->BUFFER_SIZE - (logfs->head % logfs->BUFFER_SIZE));
    memcpy(logfs->writebuffer, shift(buf, logfs->BUFFER_SIZE - (logfs->head % logfs->BUFFER_SIZE)), len + (logfs->head % logfs->BUFFER_SIZE) - logfs->BUFFER_SIZE);
  }
  else
  {
    memcpy(shift(logfs->writebuffer, (logfs->head % logfs->BUFFER_SIZE)), logfs->writebuffer, len);
  }

  logfs->head += len;

  pthread_cond_signal(&logfs->data_avail);
  pthread_mutex_unlock(&logfs->lock);

  return 1;
}

/**
 * Needs:
 *   pthread_create()
 *   pthread_join()
 *   pthread_mutex_init()
 *   pthread_mutex_destroy()
 *   pthread_mutex_lock()
 *   pthread_mutex_unlock()
 *   pthread_cond_init()
 *   pthread_cond_destroy()
 *   pthread_cond_wait()
 *   pthread_cond_signal()
 */

/* research the above Needed API and design accordingly */
