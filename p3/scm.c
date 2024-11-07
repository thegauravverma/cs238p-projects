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
   if (fstat(scm->fd, &st) == -1) {
    TRACE("Failed to Open file");
    exit(EXIT_FAILURE); /* Exit if fstat fails */
  }

  if (!S_ISREG(st.st_mode))
  {
    TRACE("Error: Not a regular file");
    exit(EXIT_FAILURE); 
  }
  scm->available_memory = descriptor_align(st.st_size);

  if (scm->available_memory < 1)
  {
    TRACE("Error: Invalid available memory size");
    exit(EXIT_FAILURE);
  }
}

struct scm *scm_open(const char *pathname, int truncate)
{
  struct scm *scm;
  size_t curr;
  size_t vm_addr;
  struct initmem *metadata;
  if (!(scm = malloc(sizeof(struct scm))))
  {
    TRACE("Failed to allocate memory for scm struct");
    return NULL;
  };

  scm->fd = open(pathname, O_RDWR);
  if (!scm->fd)
  {
   TRACE("Failed to open file");
    free(scm);
    return NULL;
  }

  set_file_size(scm);     /* Set the file size and available memory in scm */
  curr = (size_t)sbrk(0); /* Gets the current breakline */
  vm_addr = descriptor_align(VM_ADDR);

  if (vm_addr < curr)
  {
    TRACE("Error: address is below program break");
    close(scm->fd);
    free(scm);
    exit(EXIT_FAILURE); 
  }

  scm->mem = mmap((void *)vm_addr, scm->available_memory, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, scm->fd, 0);
  if (scm->mem == MAP_FAILED)
  {
    TRACE("Failed to map memory");
    close(scm->fd);
    free(scm);
    return NULL;
  }
  if(truncate) {
    if(ftruncate(scm->fd, (long) scm->available_memory) == -1) {
      TRACE("Failed to truncate file");
      close(scm->fd);
      free(scm);
      return NULL;
    }
    scm->memory_in_use = 0;
  }
  /* Size and sign initialization */
  metadata = (struct initmem *)scm->mem;
  if (!metadata)
  {
    TRACE("Error: Failed to access metadata");
    scm_close(scm);
    return NULL;
  }
  if (truncate || metadata->sign != SIGNATURE || metadata->checksum != (SIGNATURE ^ metadata->size)) {

    metadata->sign = SIGNATURE;
    metadata->size = 0;
    metadata->checksum =SIGNATURE ^ metadata->size;
  } else {
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
    size_t n = strlen(s) ;
    char *p;
    if (!(p = scm_malloc(scm, n))) {
        TRACE(0);
        return NULL;
    }
    memcpy(p, s, n);
    return p;
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
  return  (char *)scm->mem ;
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
