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

struct device
{
  int fd;
  uint64_t size;  /* immutable */
  uint64_t block; /* immutable */
};

struct logfs
{
  void *writebuffer;          /* Buffer to write to, aligned */
  void *writebuffer_toDelete; /* Buffer to write to, unaligned to delete on close */

  void *readbuffer;          /* Buffer to read from, aligned */
  void *readbuffer_toDelete; /* Buffer to read from, unaligned to delete on close */
  uint64_t *readblock_check; /* A list of a block attached to each readbuffer slot */
  uint8_t *readblock_valid;  /* A list of if the slot is valid */

  size_t BUFFER_SIZE; /* The buffer size. A constant */
  size_t BLOCK_SIZE;  /* The block size. A constant */
  size_t head;        /* The offset on the buffer to write to */
  size_t tail;        /* The offset on the buffer to read from (for writing to disk) */

  pthread_t writer;           /* Our worker thread for writing */
  pthread_mutex_t lock;       /* A mutex to lock down our threadwork */
  pthread_cond_t data_avail;  /* Flag to mark if we have data available (if we can write more to disk) */
  pthread_cond_t space_avail; /* Flag to mark if we have space available (if we can write more to buffer) */

  struct device *device; /* Device */

  int done; /* If we are done. For closing up threadwork */
};

size_t size(struct logfs *logfs)
{
  return (logfs->head - logfs->tail) % WCACHE_BLOCKS;
}

void *writer(void *arg)
{
  struct logfs *logfs = (struct logfs *)arg;

  pthread_mutex_lock(&logfs->lock);
  while (!logfs->done)
  {
    if (size(logfs) < logfs->BLOCK_SIZE)
    {
      /* TODO: Can we flush here? SHOULD we flush here? */
      pthread_cond_wait(&logfs->data_avail, &logfs->lock);
      continue;
    }

    device_write(logfs->device, shift(logfs->writebuffer, (logfs->tail % logfs->BUFFER_SIZE)), logfs->tail, logfs->BLOCK_SIZE);
    logfs->tail += logfs->BLOCK_SIZE;

    pthread_cond_signal(&logfs->space_avail);
  }

  pthread_mutex_unlock(&logfs->lock);

  return NULL;
}

struct logfs *logfs_open(const char *pathname)
{
  struct logfs *logfs;
  unsigned i;

  if (!(logfs = malloc(sizeof(struct logfs))))
  {
    TRACE("Could not malloc logfs struct. ");
    exit(1);
  }

  if (!(logfs->device = device_open(pathname)))
  {
    TRACE("^");
    exit(1);
  }

  logfs->BLOCK_SIZE = device_block(logfs->device);
  logfs->BUFFER_SIZE = WCACHE_BLOCKS * logfs->BLOCK_SIZE;

  logfs->writebuffer_toDelete = malloc((WCACHE_BLOCKS + 1) * logfs->BLOCK_SIZE);
  logfs->writebuffer = memory_align(logfs->writebuffer_toDelete, logfs->BLOCK_SIZE);

  logfs->readbuffer_toDelete = malloc((RCACHE_BLOCKS + 1) * logfs->BLOCK_SIZE);
  logfs->readbuffer = memory_align(logfs->readbuffer_toDelete, logfs->BLOCK_SIZE);

  /* Initializing the labels for each blockslot */
  logfs->readblock_check = malloc(RCACHE_BLOCKS * sizeof(uint64_t));
  logfs->readblock_valid = malloc(RCACHE_BLOCKS * sizeof(uint8_t));
  for (i = 0; i < RCACHE_BLOCKS; ++i)
  {
    logfs->readblock_check[i] = 0;
    logfs->readblock_valid[i] = 0;
  }

  logfs->head = 0;
  logfs->tail = 0;

  if (pthread_create(&logfs->writer, NULL /* TODO: Find attributes */, writer, logfs))
  {
    TRACE("Failed to create writer thread.");
    exit(1);
  }

  if (pthread_mutex_init(&logfs->lock, NULL /* TODO: Find attributes */))
  {
    TRACE("Failed to create threadlock.");
    exit(1);
  }

  if (pthread_cond_init(&logfs->data_avail, NULL /* TODO: Find attributes */))
  {
    TRACE("Failed to create data_avail condition.");
    exit(1);
  }

  if (pthread_cond_init(&logfs->space_avail, NULL /* TODO: Find attributes */))
  {
    TRACE("Failed to create space_avail condition.");
    exit(1);
  }

  logfs->done = 0;

  return logfs;
}

void logfs_close(struct logfs *logfs)
{
  logfs->done = 1;
  pthread_cond_signal(&logfs->data_avail);
  pthread_join(logfs->writer, NULL);

  pthread_cond_destroy(&logfs->data_avail);
  pthread_cond_destroy(&logfs->space_avail);

  pthread_mutex_destroy(&logfs->lock);
  /*pthread_???(&logfs->writer);*/

  free(logfs->writebuffer_toDelete);
  free(logfs->readbuffer_toDelete);
  free(logfs->readblock_check);
  free(logfs->readblock_valid);

  free(logfs);
}

void cache_miss(struct logfs *logfs, uint64_t block)
{
  /* Copy over the device block to the readbuffer */
  void *readbuffer_block = shift(logfs->readbuffer, (block % RCACHE_BLOCKS) * logfs->BLOCK_SIZE);
  if (device_read(logfs->device, readbuffer_block, block * logfs->BLOCK_SIZE, logfs->BLOCK_SIZE))
  {
    /* Error and exit */
  }
  else
  {
    logfs->readblock_check[block % RCACHE_BLOCKS] = block;
    logfs->readblock_valid[block % RCACHE_BLOCKS] = 1;
  }
  /* Else we did it */
}

int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len)
{
  /* Pseudo:
  0) Create currlen -> 0
  1) For each block in [off, off+len)...
  2)   Get the block alignment mod RCACHE_BLOCKS -> blk
  3)   if blk not in readbuffer, copy it to readbuffer
  4)   read from readbuffer to buf
  */
  uint64_t currlen = 0;
  uint64_t currblock = get_block(off, logfs->BLOCK_SIZE);

  /* Check for cache miss on initial block */
  if (!logfs->readblock_valid[currblock % RCACHE_BLOCKS] || logfs->readblock_check[currblock % RCACHE_BLOCKS] != currblock)
  {
    cache_miss(logfs, currblock);
  }

  /* Initial block - if we don't need to get to the end of the block */
  if (currblock == get_block(off + len, logfs->BLOCK_SIZE))
  {
    memcpy(buf, shift(logfs->readbuffer, off), len);
    return 0; /* Done */
  }

  /* Initial block - Otherwise we need to get to the end of the block */
  memcpy(buf, shift(logfs->readbuffer, off), logfs->BLOCK_SIZE - (off % logfs->BLOCK_SIZE));
  currlen += off % logfs->BLOCK_SIZE;
  ++currblock;

  while (currlen + logfs->BLOCK_SIZE <= len)
  {
    /* We can copy a full block */
    if (!logfs->readblock_valid[currblock % RCACHE_BLOCKS] || logfs->readblock_check[currblock % RCACHE_BLOCKS] != currblock)
    {
      cache_miss(logfs, currblock);
    }

    memcpy(shift(buf, currlen), shift(logfs->readbuffer, off + currlen), logfs->BLOCK_SIZE);
    currlen += logfs->BLOCK_SIZE;
    ++currblock;
  }

  /* Getting the last bit of data, not a full block (because of the above), if not nothing */
  if (currlen == len)
  {
    return 0;
  }

  if (!logfs->readblock_valid[currblock % RCACHE_BLOCKS] || logfs->readblock_check[currblock % RCACHE_BLOCKS] != currblock)
  {
    cache_miss(logfs, currblock);
  }

  memcpy(shift(buf, currlen), shift(logfs->readbuffer, off + currlen), len - currlen);
  return 0;
}

int logfs_append(struct logfs *logfs, const void *buf, uint64_t len)
{
  if ((logfs->head + len) > logfs->device->size)
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
