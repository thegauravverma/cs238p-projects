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
  void *block_start;
  size_t block_size;
  struct free_block *next;
};

struct scm
{
  size_t memory_in_use;    /* Currently used memory */
  size_t available_memory; /* Available memory */

  int fd;    /* Kernel abstraction for address of the memory */
  void *mem; /* Start of memory allocation */

  struct free_block *free_list; /* Tracks */
};

struct initmem
{
  uint8_t sign;     /* Signature */
  uint8_t size;     /* Memory in use */
  uint8_t checksum; /* Checksum function */
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

  TRACE("Opening... ");

  if (!(scm = malloc(sizeof(struct scm))))
  {
    /* Error and exit */
  };

  scm->free_list = NULL;

  if (truncate)
  {
    /* Fill the file with zero's initially */
  }

  scm->fd = open(pathname, O_RDWR);
  if (!scm->fd)
  {
    /* Error and exit */
  }

  TRACE("Opened... ");

  set_file_size(scm);     /* Error checking done inside fn */
  curr = (size_t)sbrk(0); /* Gets the current breakline */
  vm_addr = descriptor_align(VM_ADDR);

  if (vm_addr < curr)
  {
    /* Error and exit */
  }

  TRACE("Mapping... ");

  scm->mem = mmap((void *)vm_addr, scm->available_memory, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, scm->fd, 0);
  if (scm->mem == MAP_FAILED)
  {
    /* Error and exit */
  }

  /* Size and sign initialization */
  scm->memory_in_use = 0;
  if (!(scm->mem = scm_malloc(scm, sizeof(struct initmem))))
  {
    /* Error and exit */
    TRACE("Couldn't assign memory for initial 24!");
    exit(0);
  }

  TRACE("Helping... ");
  ((struct initmem *)scm->mem)->sign = 0; /* TODO */
  TRACE("Above breaking");
  ((struct initmem *)scm->mem)->size = scm->memory_in_use;
  ((struct initmem *)scm->mem)->checksum = scm->memory_in_use;

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
  struct free_block *curr = scm->free_list;
  struct free_block *next;
  void *ptr;

  /* Check if the free list exists */
  if (!curr)
  {
    return NULL;
  }

  /* We have to operate a bit differently on the first elem in the linked list. */
  /* If we can use it exactly, we assign the next item in the list to the head. */
  if (N == curr->block_size)
  {
    scm->free_list = curr->next;
    ptr = curr->block_start;
    free(curr);
    return ptr;
  }

  /* Else, if we can use the first block, we will adjust the block. */
  if (N < curr->block_size)
  {
    ptr = curr->block_start;
    curr->block_start = shift(curr->block_start, N);
    return ptr;
  }

  /* Otherwise we check the next blocks... */
  while (curr->next)
  {
    if (N == curr->next->block_size)
    {
      next = curr->next->next;
      ptr = curr->next->block_start;
      free(curr->next);
      curr->next = next;
      return ptr;
    }
    if (N < curr->next->block_size)
    {
      ptr = curr->next->block_start;
      curr->next->block_start = shift(curr->next->block_start, N);
      return ptr;
    }
  }

  /* If nothing was found, we don't return anything */
  return NULL;
}

void *scm_malloc(struct scm *scm, size_t N)
{
  void *ptr;
  TRACE("Free check");
  if ((ptr = check_free_list(scm, N)))
  {
    return ptr;
  }

  TRACE("Past free check");

  if ((scm->memory_in_use + N) > scm->available_memory)
  {
    /* Exit and error */
    TRACE("Out of memory!");
    exit(0);
  }

  ptr = shift(scm->mem, scm->memory_in_use);
  scm->memory_in_use += N;

  TRACE("Memory used");
  return ptr;
}

char *scm_strdup(struct scm *scm, const char *s)
{
  char *word;

  if (!(word = scm_malloc(scm, sizeof(char) * safe_strlen(s))))
  {
    TRACE("Couldn't get memory from malloc!");
    exit(0);
  }
  word = (char *)s;
  return word;
}

void scm_free(struct scm *scm, void *p)
{
  struct free_block *curr;
  struct free_block *next;

  /* If we haven't begun a free list, we should start one */
  if (!scm->free_list)
  {
    scm->free_list = scm_malloc(scm, sizeof(struct free_block));
    scm->free_list->block_start = p;
    scm->free_list->block_size = sizeof(p);
    scm->free_list->next = NULL;

    free(p);
    return;
  }

  /* We potentially need to combine some blocks, do that here */
  if (shift(p, sizeof(p)) == scm->free_list->block_start)
  {
    scm->free_list->block_start = p;
    scm->free_list->block_size += sizeof(p);

    free(p);
    return;
  }

  /* Otherwise, if this free is before the first malloc, we put it at head */
  if (shift(p, sizeof(p)) < scm->free_list->block_start)
  {
    curr = scm->free_list;
    scm->free_list = scm_malloc(scm, sizeof(struct free_block));
    scm->free_list->block_start = p;
    scm->free_list->block_size = sizeof(p);
    scm->free_list->next = curr;

    free(p);
    return;
  }

  /* Otherwise we need to loop */
  curr = scm->free_list;
  while (curr->next)
  {
    if (p <= curr->next->block_start)
    {
      /* Check for start and end combination */
      if (p == shift(curr->block_start, curr->block_size) && shift(p, sizeof(p)) == curr->next->block_start)
      {
        curr->block_size += sizeof(p) + curr->next->block_size;
        next = curr->next->next;
        free(curr->next);
        curr->next = next;

        free(p);
        return;
      }
      if (p == shift(curr->block_start, curr->block_size))
      {
        curr->block_size += sizeof(p);

        free(p);
        return;
      }
      if (shift(p, sizeof(p)) == curr->next->block_start)
      {
        curr->next->block_start = p;
        curr->next->block_size += sizeof(p);

        free(p);
        return;
      }

      /* Otherwise, stick it in the middle */
      next = curr->next;
      curr->next = scm_malloc(scm, sizeof(struct free_block));
      curr->next->block_start = p;
      curr->next->block_size = sizeof(p);
      curr->next->next = next;

      free(p);
      return;
    }

    curr = curr->next;
  }

  /* If we've reached the end, append to end */
  if (p == shift(curr->block_start, curr->block_size))
  {
    curr->block_size += sizeof(p);

    free(p);
    return;
  }

  curr->next = scm_malloc(scm, sizeof(struct free_block));
  curr->next->block_start = p;
  curr->next->block_size = sizeof(p);
  curr->next->next = NULL;

  free(p);
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
