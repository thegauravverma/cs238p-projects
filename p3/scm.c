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
#define SIGNATURE 73

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
  scm->fd = open(pathname, O_RDWR);
  if (!scm->fd)
  {
    /* Error and exit */
  }

  set_file_size(scm);     /* Error checking done inside fn */
  curr = (size_t)sbrk(0); /* Gets the current breakline */
  vm_addr = descriptor_align(VM_ADDR);
    if(truncate) {
    if(ftruncate(scm->fd, (long) scm->available_memory) == -1) {
          close(scm->fd);
            free(scm);
            TRACE("ftruncate failed");
            return NULL;
    };
  }
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
  metadata = (struct initmem *)scm->mem;
  if (!metadata)
  {
    /* Error and exit */
  }
  if (truncate || metadata->sign != SIGNATURE || metadata->checksum != (SIGNATURE ^ metadata->size)) {
    printf("Sign: %d, Size: %d, Checksum: %d\n", metadata->sign, metadata->size, metadata->checksum);
    metadata->sign = SIGNATURE;
    metadata->size = 0;
    metadata->checksum =SIGNATURE ^ metadata->size;
    scm->memory_in_use = sizeof(struct initmem);
  } else {
      printf("here");
      printf("Sign: %d, Size: %d, Checksum: %d\n", metadata->sign, metadata->size, metadata->checksum);
    scm->memory_in_use = metadata->size;
  }
  return scm;
}

void scm_close(struct scm *scm)
{
  if (scm->mem)
  {
    struct initmem *metadata = (struct initmem *)scm->mem;
    metadata->size = scm->memory_in_use;
    metadata->sign = SIGNATURE;
    metadata->checksum = SIGNATURE ^ metadata->size;
    printf("Sign: %d, Size: %d, Checksum: %d\n", metadata->sign, metadata->size, metadata->checksum);
    msync(scm->mem, scm->available_memory, MS_SYNC);
    munmap(scm->mem, scm->available_memory);
  }
  if (scm->fd)
  {
    close(scm->fd);
  }
  free(scm);
}

void *scm_malloc(struct scm *scm, size_t N)
{
    void *ptr;
    if ((scm->memory_in_use + N) > scm->available_memory) {
        TRACE("Not Enough Memory for Allocation.");
        return NULL;
    }

    ptr = (uint8_t *)scm->mem + scm->memory_in_use;
    scm->memory_in_use += N;

    return ptr;
}

char *scm_strdup(struct scm *scm, const char *s)
{
  size_t str_len;
  char *dup_str;
  size_t i;
  if (!s) {
    TRACE("Given string is NULL");
    return NULL;
  }
  str_len = strlen(s) + 1;
  if (!(dup_str = scm_malloc(scm, str_len))) {
    TRACE(0);
    return NULL;
  }
  for (i = 0; i < str_len; i++) {
    dup_str[i] = s[i];
  }
  return dup_str;
}

void scm_free(struct scm *scm, void *p)
{
  UNUSED(scm);
  UNUSED(p);
  /* STUB */
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
