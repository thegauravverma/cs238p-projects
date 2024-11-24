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

  uint64_t WBUFFER_SIZE; /* The buffer size for the write buffer. A constant */
  uint64_t RBUFFER_SIZE; /* The buffer size for the read buffer. A constant */
  uint64_t BLOCK_SIZE;   /* The block size. A constant */
  uint64_t head;         /* The offset on the buffer to write to */
  uint64_t tail;         /* The offset on the buffer to read from (for writing to disk) */
  uint64_t writerEnd;  
  uint64_t read_head;       
  uint64_t read_tail;        

  pthread_t writer;           /* Our worker thread for writing */
  pthread_mutex_t lock;       /* A mutex to lock down our threadwork */
  pthread_cond_t data_avail;  /* Flag to mark if we have data available (if we can write more to disk) */
  pthread_cond_t space_avail; /* Flag to mark if we have space available (if we can write more to buffer) */

  struct device *device; /* Device */
  uint64_t device_written;
  int is_reading;
  int is_writing;
  int done; /* If we are done. For closing up threadwork */
};

size_t logfs_size(struct logfs *logfs)
{
  return (logfs->head - logfs->tail) % logfs->WBUFFER_SIZE;
}



void logfs_flush_data_to_device(struct logfs *logfs, uint64_t start, uint64_t end)
{
    void *temp_mem;
    void *temp_mem_to_delete;
    uint64_t len;
    uint64_t rem_len;
    uint64_t block_off;
    uint64_t rem_bytes;

    if (start == end)
    {
        return;
    }

    block_off = logfs->device_written % logfs->BLOCK_SIZE;
    if (block_off > 0)
    {
        rem_bytes = logfs->BLOCK_SIZE - block_off;

        temp_mem_to_delete = malloc(logfs->BLOCK_SIZE + logfs->BLOCK_SIZE );
        temp_mem = memory_align(temp_mem_to_delete, logfs->BLOCK_SIZE);
        memset(temp_mem, 0, logfs->BLOCK_SIZE);

        device_read(logfs->device, temp_mem, (logfs->device_written - block_off), logfs->BLOCK_SIZE);
        memcpy((char *)((char *)temp_mem + block_off), (char *)start, rem_bytes);
        device_write(logfs->device, temp_mem, (logfs->device_written - block_off),logfs->BLOCK_SIZE);

        FREE(temp_mem_to_delete);

        if ((start + rem_bytes) > end)
        {
            logfs->device_written += end - start;
            return;
        }
        else
        {
            logfs->device_written  += rem_bytes;
            start += rem_bytes;
        }
    }

    if ((start % logfs->BLOCK_SIZE) > 0)
    {
        temp_mem_to_delete = malloc(logfs->BLOCK_SIZE * WCACHE_BLOCKS + logfs->BLOCK_SIZE);
        temp_mem = memory_align(temp_mem_to_delete, logfs->BLOCK_SIZE);

        memset(temp_mem, 0, logfs->BLOCK_SIZE * WCACHE_BLOCKS);
        len = end - start;
        memcpy(temp_mem, (void *)start, len);

        logfs_flush_data_to_device(logfs, (uint64_t)temp_mem, (uint64_t)temp_mem + len);

        FREE(temp_mem_to_delete);
        return;
    }

    len = end - start;
    rem_len = len % logfs->BLOCK_SIZE;
    if (rem_len > 0)
    {
        len += logfs->BLOCK_SIZE - rem_len;
    }
    device_write(logfs->device, (void *)start, logfs->device_written, len);
    logfs->device_written += end - start;
    return;
}


int logfs_flush(struct logfs *logfs)
{
    uint64_t head_ptr = logfs->head;
    if (head_ptr < logfs->tail)
    {
        logfs_flush_data_to_device(logfs, logfs->tail, logfs->writerEnd);
        logfs_flush_data_to_device(logfs, (uint64_t)logfs->writebuffer, head_ptr);
        logfs->tail = head_ptr;
        return 0;
    }
    logfs_flush_data_to_device(logfs, logfs->tail, head_ptr);
    logfs->tail = head_ptr;
    return 0;
}

void *writer(void *arg)
{
  struct logfs *logfs = (struct logfs *)arg;
  while (!logfs->done)
  {
    pthread_mutex_lock(&logfs->lock);
    while((!logfs->done) && !logfs->is_writing) {
      pthread_cond_wait(&logfs->data_avail,&logfs->lock);
    }

    logfs_flush(logfs);

    logfs->is_writing = 0;
    logfs->is_reading = 1;
    pthread_cond_signal(&logfs->space_avail);
    pthread_mutex_unlock(&logfs->lock);
  }
  return logfs;
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
  memset(logfs->writebuffer, 0, logfs->BLOCK_SIZE * WCACHE_BLOCKS);
  if (!(logfs->readbuffer_toDelete = malloc((RCACHE_BLOCKS + 1) * logfs->BLOCK_SIZE)))
  {
    TRACE("Failed to malloc read buffer. ");
    exit(1);
  }
  logfs->readbuffer = memory_align(logfs->readbuffer_toDelete, logfs->BLOCK_SIZE);
  memset(logfs->readbuffer, 0, logfs->BLOCK_SIZE * RCACHE_BLOCKS);

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
  logfs->writerEnd = (uint64_t)logfs->writebuffer + (logfs->BLOCK_SIZE * WCACHE_BLOCKS);
  logfs->head = (uint64_t)logfs->writebuffer;
  logfs->tail = (uint64_t)logfs->writebuffer;
  logfs->read_head = 0;
  logfs->read_tail= 0;
  logfs->is_reading = 0;
  logfs->is_writing = 0;
  logfs->device_written = 0;
  if (pthread_create(&logfs->writer, NULL /* TODO: Find attributes */, writer, (void *)logfs))
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
  logfs->is_writing = 1;
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


void *logfs_reader_wait_for_data(struct logfs *logfs)
{
    pthread_mutex_lock(&logfs->lock);
    logfs->is_writing = 1;
    logfs->is_reading = 0;
    pthread_cond_signal(&logfs->data_avail);
    while(!logfs->is_reading) {
      pthread_cond_wait(&logfs->space_avail, &logfs->lock);
    }
    pthread_mutex_unlock(&logfs->lock);
    return logfs;
}


int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len)
{
  uint64_t device_size_;
    uint64_t read_addr;
    uint64_t rem_bytes;
    uint64_t aligned_read_off;
    uint64_t adj_len;
    uint64_t block_pad;

      device_size_ = device_size(logfs->device);
    if (len > device_size_ - off)
    {
        TRACE("read exceeds device size");
        return -1;
    }

    /* Check out of range */
    if ((off + len > logfs->read_tail) || off < logfs->read_head)
    {
        logfs_reader_wait_for_data(logfs);
        rem_bytes = off % logfs->BLOCK_SIZE;
        aligned_read_off = off - rem_bytes;

        adj_len = len + rem_bytes;
        block_pad = adj_len % logfs->BLOCK_SIZE;

        if (block_pad > 0)
        {
            adj_len = adj_len - block_pad + logfs->BLOCK_SIZE;
        }

        device_read(logfs->device, logfs->readbuffer, aligned_read_off, adj_len);

        logfs->read_head = aligned_read_off;
        logfs->read_tail = aligned_read_off + adj_len;

        if (logfs->read_tail > logfs->device_written)
        {
            logfs->read_tail = logfs->device_written;
        }
    }

    if ((off >= logfs->read_head) && (len <= (logfs->read_tail - logfs->read_head)))
    {
        read_addr = ((uint64_t)logfs->readbuffer) + off - logfs->read_head;
        memcpy(buf, (void *)read_addr, len);
        return 0;
    }

    return -1;
}

int logfs_append(struct logfs *logfs, const void *buf, uint64_t len)
{
  uint64_t remaining_length;
  if(logfs->head < logfs->tail) {
    remaining_length = logfs->tail - logfs->head;
  } else {
    remaining_length = logfs->writerEnd - (uint64_t)logfs->writebuffer - (logfs->head - logfs->tail);
  }
  if(len >= remaining_length) {
    logfs_reader_wait_for_data(logfs);
  }

  if(logfs->head + len <= logfs->writerEnd) {
    memcpy((void *)logfs->head,buf,len);
    logfs->head+=len;
    logfs->is_writing = 1;
    pthread_cond_signal(&logfs->data_avail);
    return 0;
  }

  remaining_length = logfs->writerEnd - logfs->head;
  memcpy((char *)logfs->head,buf,remaining_length);
  len-=remaining_length;
  memcpy((char *)logfs->writebuffer,(char *)buf + remaining_length,len);
  logfs->head = (uint64_t)logfs->writebuffer + len;
  logfs->is_writing = 1;
  pthread_cond_signal(&logfs->data_avail);
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
