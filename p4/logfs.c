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

  size_t WBUFFER_SIZE; /* The buffer size for the write buffer. A constant */
  size_t RBUFFER_SIZE; /* The buffer size for the read buffer. A constant */
  size_t BLOCK_SIZE;   /* The block size. A constant */
  size_t head;         /* The offset on the buffer to write to */
  size_t tail;         /* The offset on the buffer to read from (for writing to disk) */

  pthread_t writer;           /* Our worker thread for writing */
  pthread_mutex_t lock;       /* A mutex to lock down our threadwork */
  pthread_cond_t data_avail;  /* Flag to mark if we have data available (if we can write more to disk) */
  pthread_cond_t space_avail; /* Flag to mark if we have space available (if we can write more to buffer) */

  struct device *device; /* Device */

  int done; /* If we are done. For closing up threadwork */
};

size_t logfs_size(struct logfs *logfs)
{
  return (logfs->head - logfs->tail) % logfs->WBUFFER_SIZE;
}

int flush(struct logfs *logfs)
{
  uint64_t original_head;
  uint64_t original_tail;
  size_t pending_size;
  pthread_mutex_lock(&logfs->lock);

  /* We're going to fully write before flushing to preserve the tail correctly! */
  while (logfs_size(logfs) >= logfs->BLOCK_SIZE)
  {
    TRACE("Waiting on writer for further flushing...");
    pthread_cond_signal(&logfs->data_avail);
    pthread_cond_wait(&logfs->space_avail, &logfs->lock);
    TRACE("Waiting complete!");
  }

  original_head = logfs->head;
  original_tail = logfs->tail;
  printf("Tail: %ld\n", logfs->tail);
  pending_size = logfs->head - logfs->tail;

  if (pending_size == 0)
  {
    /* No data to flush*/
    pthread_mutex_unlock(&logfs->lock);
    return 0;
  }

  logfs->head += logfs->BLOCK_SIZE - pending_size;
  assert(logfs->head % logfs->BLOCK_SIZE == 0);
  while (logfs_size(logfs) != 0)
  {
    pthread_cond_signal(&logfs->data_avail);
    pthread_cond_wait(&logfs->space_avail, &logfs->lock);
  }

  logfs->head = original_head;
  logfs->tail = original_tail;
  TRACE("Never mind.");

  pthread_mutex_unlock(&logfs->lock);

  return 0;
}

void *writer(void *arg)
{
  struct logfs *logfs = (struct logfs *)arg;

  pthread_mutex_lock(&logfs->lock);
  while (!logfs->done)
  {
    if (logfs_size(logfs) < logfs->BLOCK_SIZE)
    {
      pthread_cond_wait(&logfs->data_avail, &logfs->lock);
      continue;
    }

    if (device_write(logfs->device, logfs->writebuffer, logfs->tail % logfs->WBUFFER_SIZE, logfs->BLOCK_SIZE) == -1)
    {
      TRACE(0);
      exit(1);
    }
    TRACE("Moving tail up!!");
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
  logfs->WBUFFER_SIZE = WCACHE_BLOCKS * logfs->BLOCK_SIZE;
  logfs->RBUFFER_SIZE = RCACHE_BLOCKS * logfs->BLOCK_SIZE;

  if (!(logfs->writebuffer_toDelete = malloc((WCACHE_BLOCKS + 1) * logfs->BLOCK_SIZE)))
  {
    TRACE("Failed to malloc write buffer. ");
    exit(1);
  }
  logfs->writebuffer = memory_align(logfs->writebuffer_toDelete, logfs->BLOCK_SIZE);

  if (!(logfs->readbuffer_toDelete = malloc((RCACHE_BLOCKS + 1) * logfs->BLOCK_SIZE)))
  {
    TRACE("Failed to malloc read buffer. ");
    exit(1);
  }
  logfs->readbuffer = memory_align(logfs->readbuffer_toDelete, logfs->BLOCK_SIZE);

  /* Initializing the labels for each blockslot */
  if (!(logfs->readblock_check = malloc(RCACHE_BLOCKS * sizeof(uint64_t))))
  {
    TRACE("Failed to malloc read buffer block tracking.");
  }

  if (!(logfs->readblock_valid = malloc(RCACHE_BLOCKS * sizeof(uint8_t))))
  {
    TRACE("Failed to malloc read buffer valid tracking.");
  }

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
  if (device_read(logfs->device, shift(logfs->readbuffer, (block * logfs->BLOCK_SIZE) % logfs->RBUFFER_SIZE), block * logfs->BLOCK_SIZE, logfs->BLOCK_SIZE))
  {
    TRACE(0);
    exit(1);
  }

  printf("We wrote on block %ld with offset %ld with BLOCK_SIZE\n", block, block * logfs->BLOCK_SIZE);

  logfs->readblock_check[block % RCACHE_BLOCKS] = block;
  logfs->readblock_valid[block % RCACHE_BLOCKS] = 1;
  /* Else we did it */
}

int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len)
{
  uint64_t currlen, currblock;
  if (flush(logfs))
  {
    TRACE("Flush failed during read.");
    return -1;
  }

  currlen = 0;
  currblock = get_block(off, logfs->BLOCK_SIZE);
  printf("Currblock: %ld\n", currblock);

  /* Check for cache miss on initial block */
  if (currblock == get_block(logfs->head, logfs->BLOCK_SIZE) || !logfs->readblock_valid[currblock % RCACHE_BLOCKS] || logfs->readblock_check[currblock % RCACHE_BLOCKS] != currblock)
  {
    printf("CompareBlock: %ld\n", get_block(logfs->head, logfs->BLOCK_SIZE));
    cache_miss(logfs, currblock);
  }

  /* Initial block - if we don't need to get to the end of the block */
  if (currblock == get_block(off + len - 1, logfs->BLOCK_SIZE))
  {
    memcpy(buf, shift(logfs->readbuffer, off % logfs->RBUFFER_SIZE), len);
    return 0; /* Done */
  }

  /* Initial block - Otherwise we need to get to the end of the block */
  printf("Off: %ld, CurrLen: %ld, Len: %ld, RBUFFER_SIZE: %ld\n", off, currlen, len, logfs->RBUFFER_SIZE);
  memcpy(buf, shift(logfs->readbuffer, off % logfs->RBUFFER_SIZE), logfs->BLOCK_SIZE - (off % logfs->BLOCK_SIZE));
  currlen += logfs->BLOCK_SIZE - (off % logfs->BLOCK_SIZE);
  ++currblock;
  if (*(char *)(buf) == '\0')
  {
    TRACE("First letter is null! Off by one!!");
  }
  TRACE((char *)buf);
  printf("Buffer: %.*s\n", (int)(logfs->BLOCK_SIZE), (char *)logfs->writebuffer);

  TRACE("Reading...");
  while (currlen + logfs->BLOCK_SIZE <= len)
  {
    TRACE("While Loop");
    /* We can copy a full block */
    if (!logfs->readblock_valid[currblock % RCACHE_BLOCKS] || logfs->readblock_check[currblock % RCACHE_BLOCKS] != currblock)
    {
      cache_miss(logfs, currblock);
    }

    memcpy(shift(buf, currlen), shift(logfs->readbuffer, (off + currlen) % logfs->RBUFFER_SIZE), logfs->BLOCK_SIZE);
    currlen += logfs->BLOCK_SIZE;
    ++currblock;
  }

  TRACE("Getting the last block");
  /* Getting the last bit of data, not a full block (because of the above), if not nothing */
  if (currlen == len)
  {
    TRACE("Exiting cos we're done");
    return 0;
  }

  TRACE((char *)buf);

  if (!logfs->readblock_valid[currblock % RCACHE_BLOCKS] || logfs->readblock_check[currblock % RCACHE_BLOCKS] != currblock)
  {
    TRACE("Cache missing in last thing");
    cache_miss(logfs, currblock);
  }

  printf("Read buffer offset: %.*s\n", (int)(len - currlen), (char *)shift(logfs->readbuffer, (off + currlen) % logfs->RBUFFER_SIZE));
  printf("Off: %ld, CurrLen: %ld, Len: %ld, RBUFFER_SIZE: %ld\n", off, currlen, len, logfs->RBUFFER_SIZE);
  memcpy(shift(buf, currlen), shift(logfs->readbuffer, (off + currlen) % logfs->RBUFFER_SIZE), len - currlen);
  TRACE((char *)buf);
  printf("%c\n", ((char *)buf)[0]);
  printf("%c\n", ((char *)buf)[1]);
  return 0;
}

int logfs_append(struct logfs *logfs, const void *buf, uint64_t len)
{
  if ((logfs->head + len) > logfs->device->size)
  {
    TRACE("Cannot write further to the device.");
    return 1;
  }
  pthread_mutex_lock(&logfs->lock);

  assert(len <= logfs->WBUFFER_SIZE);
  for (;;)
  {
    if ((logfs->WBUFFER_SIZE - logfs_size(logfs)) < len)
    {
      pthread_cond_wait(&logfs->space_avail, &logfs->lock);
      continue;
    }
    break;
  }

  printf("Head: %ld, Len: %ld\n", logfs->head, len);
  if ((logfs->head % logfs->WBUFFER_SIZE) + len > logfs->WBUFFER_SIZE)
  {
    TRACE("Entering double case");
    memcpy(shift(logfs->writebuffer, (logfs->head % logfs->WBUFFER_SIZE)), buf, logfs->WBUFFER_SIZE - (logfs->head % logfs->WBUFFER_SIZE));
    memcpy(logfs->writebuffer, shift(buf, logfs->WBUFFER_SIZE - (logfs->head % logfs->WBUFFER_SIZE)), len + (logfs->head % logfs->WBUFFER_SIZE) - logfs->WBUFFER_SIZE);
  }
  else
  {
    TRACE("Entering single case");
    memcpy(shift(logfs->writebuffer, (logfs->head % logfs->WBUFFER_SIZE)), buf, len);
    TRACE((char *)shift(logfs->writebuffer, logfs->head));
    printf("We just wrote %.*s to offset %ld\n", (int)len, (char *)buf, logfs->head);
  }

  logfs->head += len;
  pthread_cond_signal(&logfs->data_avail);
  pthread_mutex_unlock(&logfs->lock);

  return 0;
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
