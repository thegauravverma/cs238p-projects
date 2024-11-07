/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * scm.c
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "scm.h"

#define VM_ADDR 0x600000000000

struct free_block
{
  size_t block_start; /* Start of our freelist, offset by mem */
  size_t block_size;  /* Block size for the freeblock */
  size_t next;        /* Next block; 0 when null */
};

struct scm
{
  size_t memory_in_use;    /* Currently used memory */
  size_t available_memory; /* Available memory */

  int fd;    /* Kernel abstraction for address of the memory */
  void *mem; /* Start of memory allocation */
};

struct initmem
{
  uint8_t sign;     /* Signature */
  uint8_t size;     /* Memory in use */
  uint8_t checksum; /* Checksum function */
  uint8_t freelist; /* Free list */
};

void set_file_size(struct scm *scm)
{
  /* Check that the file's open */
  struct stat st;
  fstat(scm->fd, &st);

  if (!S_ISREG(st.st_mode))
  {
    /* Error and exit */
  }
  scm->available_memory = descriptor_align(st.st_size);

  if (scm->available_memory < 1)
  {
    /* Error and exit */
  }

  /** Lecture requested to return status, but if we error check inside this fn we are golden **/
}

struct scm *scm_open(const char *pathname, int truncate)
{
  struct scm *scm;
  size_t curr;
  size_t vm_addr;
  struct initmem *metadata;
  if (!(scm = malloc(sizeof(struct scm))))
  {
    /* Error and exit */
  };

  if (truncate)
  {
    scm->fd = open(pathname, O_RDWR | O_TRUNC);
  }
  else
  {
    scm->fd = open(pathname, O_RDWR);
  }
  if (!scm->fd)
  {
    /* Error and exit */
  }

  set_file_size(scm);     /* Error checking done inside fn */
  curr = (size_t)sbrk(0); /* Gets the current breakline */
  vm_addr = descriptor_align(VM_ADDR);

  if (vm_addr < curr)
  {
    /* Error and exit */
  }

  scm->mem = mmap((void *)vm_addr, scm->available_memory, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, scm->fd, 0);
  if (scm->mem == MAP_FAILED)
  {
    /* Error and exit */
  }

  /* Size and sign initialization */
  metadata = (struct initmem *)scm_malloc(scm, sizeof(struct initmem));
  if (!metadata)
  {
    /* Error and exit */
  }
  if (truncate || metadata->sign != 73 || metadata->checksum != (metadata->sign ^ metadata->size))
  {
    metadata->sign = 73;
    metadata->size = 0;
    metadata->checksum = metadata->sign ^ metadata->size;
    metadata->freelist = 0;
    scm->memory_in_use = sizeof(struct initmem);
  }
  else
  {
    scm->memory_in_use = metadata->size;
  }
  return scm;
}

void scm_close(struct scm *scm)
{
  if (scm->memory_in_use /** MIGHT BE WRONG **/)
  {
    msync((void *)scm->memory_in_use, scm->available_memory, MS_SYNC);
    munmap((void *)scm->memory_in_use, scm->available_memory);
  }
  if (scm->fd)
  {
    close(scm->fd);
  }
  free(scm);
}

void *check_free_list(struct scm *scm, size_t N)
{
  struct free_block *freelist;
  struct free_block *curr;
  struct free_block *next;

  /* Check if the free list exists */
  if ((!(struct initmem *)scm->mem) || (((struct initmem *)scm->mem)->freelist == 0))
  {
    return NULL;
  }

  freelist = shift(scm->mem, ((struct initmem *)scm->mem)->freelist);
  curr = freelist;

  /* Check if we can use the first block */
  if (N == curr->block_size)
  {
    ((struct initmem *)scm->mem)->freelist = curr->next;
    return curr;
  }

  /* We still check if we can use part of the first block */
  if (N < curr->block_size)
  {
    curr->block_size -= N;
    return shift(freelist, curr->block_start + curr->block_size - N);
  }

  while (curr->next != 0)
  {
    next = shift(freelist, curr->next);
    if (N == next->block_size)
    {
      curr->next = next->next;
      return next;
    }

    if (N < next->block_size)
    {
      next->block_size -= N;
      return shift(freelist, next->block_start + next->block_size - N);
    }
  }

  return NULL;
}

void *scm_malloc_free_block(struct scm *scm)
{
  void *ptr;
  struct initmem *metadata;

  if ((scm->memory_in_use + sizeof(struct free_block)) > scm->available_memory)
  {
    TRACE("Not Enough Memory for Allocation.");
  }

  ptr = (uint8_t *)scm->mem + scm->memory_in_use;
  scm->memory_in_use += sizeof(struct free_block);

  metadata = (struct initmem *)scm->mem;
  metadata->size = scm->memory_in_use;
  metadata->checksum = metadata->sign ^ metadata->size;

  return ptr;
}

void *scm_malloc(struct scm *scm, size_t N)
{
  void *ptr;
  struct initmem *metadata;

  if ((ptr = check_free_list(scm, N)))
  {
    return ptr;
  }

  if ((scm->memory_in_use + N) > scm->available_memory)
  {
    TRACE("Not Enough Memory for Allocation.");
  }

  ptr = (uint8_t *)scm->mem + scm->memory_in_use;
  scm->memory_in_use += N;

  metadata = (struct initmem *)scm->mem;
  metadata->size = scm->memory_in_use;
  metadata->checksum = metadata->sign ^ metadata->size;

  return ptr;
}

char *scm_strdup(struct scm *scm, const char *s)
{
  size_t str_len;
  char *dup_str;
  if (!s)
  {
    TRACE("Given string is NULL");
    return NULL;
  }
  str_len = strlen(s) + 1;
  if (!(dup_str = scm_malloc(scm, str_len)))
  {
    TRACE(0);
    return NULL;
  }
  memcpy(dup_str, s, str_len);
  return dup_str;
}

void scm_free(struct scm *scm, void *p)
{
  struct free_block *freelist;
  struct free_block *curr;
  struct free_block *next;

  size_t block_start = (size_t)p - (size_t)scm->mem;
  size_t block_end = block_start + sizeof(p);

  freelist = shift(scm->mem, ((struct initmem *)scm->mem)->freelist);

  /* If we don't find a freelist, we should start one */
  if (freelist->block_start == 0)
  {
    freelist->block_start = (size_t)p - (size_t)scm->mem;
    freelist->block_size = sizeof(p);
    freelist->next = 0;
    return;
  }

  /* Else we want to check the start, see if we can combine... */
  if (block_end == freelist->block_start)
  {
    freelist->block_start = block_start;
    freelist->block_size += sizeof(p);
    return;
  }

  /* Else, if we can't combine, and if we should insert at the start, we will */
  if (block_end < freelist->block_start)
  {
    if (!(curr = scm_malloc_free_block(scm)))
    {
      TRACE("No memory remaining in freelist allocation!");
      exit(1);
    }
    curr->block_start = block_start;
    curr->block_size = sizeof(p);
    curr->next = freelist->next;
    ((struct initmem *)scm->mem)->freelist = (size_t)curr - (size_t)scm->mem;
    return;
  }

  /* Otherwise, we need to continue in the list */
  curr = freelist;
  while (curr->next != 0)
  {
    next = (struct free_block *)shift(scm->mem, curr->next);

    /* Check if we can combine with beginning and end */
    if (block_start == curr->block_start + curr->block_size && block_end == next->block_start)
    {
      /* We adjust the size and next of the first free_block, then delete the other */
      curr->block_size += sizeof(p) + next->block_size;
      curr->next = next->next;
      scm_free(scm, next);
      return;
    }

    /* Then if we can combine with the beginning */
    if (block_start == curr->block_start + curr->block_size)
    {
      curr->block_size += sizeof(p);
      return;
    }

    /* And if we can combine with the end */
    if (block_end == next->block_start)
    {
      next->block_start -= sizeof(p);
      next->block_size += sizeof(p);
      return;
    }

    /* Else if it's somewhere in the middle */
    if (block_end < next->block_start)
    {
      /* I use freelist as a temp variable to save memory here */
      freelist = scm_malloc_free_block(scm);
      freelist->block_start = block_start;
      freelist->block_size = sizeof(p);
      freelist->next = (size_t)next - (size_t)scm->mem;
      curr->next = (size_t)freelist - (size_t)scm->mem;
      return;
    }

    /* Otherwise we iterate */
    curr = next;
  }

  /* We need to check for the last combination */
  if (block_start == curr->block_start + curr->block_size)
  {
    curr->block_size += sizeof(p);
    return;
  }

  /* Otherwise, we stick it at the end */
  next = scm_malloc_free_block(scm);
  next->block_start = block_start;
  next->block_size = sizeof(p);
  next->next = 0;
  curr->next = (size_t)next - (size_t)scm->mem;
  return;
}

size_t scm_utilized(const struct scm *scm)
{
  return scm->memory_in_use;
}

size_t scm_capacity(const struct scm *scm)
{
  return scm->available_memory;
}

void *scm_mbase(struct scm *scm)
{
  return scm->mem;
}

/**
 * Needs:
 *   fstat()
 *   S_ISREG()
 *   open()
 *   close()
 *   sbrk()
 *   mmap()
 *   munmap()
 *   msync()
 */

/* research the above Needed API and design accordingly */
