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

/* Structure representing the shared memory control (scm) */
struct scm
{
  size_t memory_in_use;    /* Currently used memory */
  size_t available_memory; /* Available memory */

  int fd;    /* File descriptor for shared memory */
  void *mem; /* Start of memory allocation */
};

/* Metadata structure for tracking memory usage and integrity */
struct initmem
{
  uint64_t sign;     /* Signature */
  uint64_t size;     /* Memory in use */
  uint64_t checksum; /* Checksum function */
};

/* Sets the file size and updates available memory in scm */
void set_file_size(struct scm *scm)
{
  struct stat st;

  /* Check if file is open */
  if (fstat(scm->fd, &st) == -1) {
    TRACE("Failed to open file");
    exit(EXIT_FAILURE); /* Exit if fstat fails */
  }

  /* Ensure the file is a regular file */
  if (!S_ISREG(st.st_mode))
  {
    TRACE("Error: Not a regular file");
    exit(EXIT_FAILURE); 
  }
  
  /* Align the file size and set available memory */
  scm->available_memory = descriptor_align(st.st_size);

  /* Check for valid memory size */
  if (scm->available_memory < 1)
  {
    TRACE("Error: Invalid available memory size");
    exit(EXIT_FAILURE);
  }
}

/* Opens and initializes shared memory */
struct scm *scm_open(const char *pathname, int truncate)
{
  struct scm *scm;
  size_t curr;
  size_t vm_addr;
  struct initmem *metadata;

  /* Allocate memory for scm structure */
  scm = malloc(sizeof(struct scm));
  if (!scm)
  {
    TRACE("Failed to allocate memory for scm struct");
    return NULL;
  }

  /* Open the file in read-write mode */
  scm->fd = open(pathname, O_RDWR);
  if (scm->fd == -1)
  {
    TRACE("Failed to open file");
    free(scm);
    return NULL;
  }

  /* Set the file size and available memory */
  set_file_size(scm);

  /* Get the current program break */
  curr = (size_t)sbrk(0);
  vm_addr = descriptor_align(VM_ADDR);

  /* Ensure the mapped address is above the program break */
  if (vm_addr < curr)
  {
    TRACE("Error: address is below program break");
    close(scm->fd);
    free(scm);
    exit(EXIT_FAILURE);
  }

  /* Map the file to memory */
  scm->mem = mmap((void *)vm_addr, scm->available_memory, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, scm->fd, 0);
  if (scm->mem == MAP_FAILED)
  {
    TRACE("Failed to map memory");
    close(scm->fd);
    free(scm);
    return NULL;
  }

  /* Initialize or verify metadata */
  metadata = (struct initmem *)scm->mem;
  if (truncate)
  {
    scm->memory_in_use = 0;
    metadata->sign = SIGNATURE;
    metadata->size = 0;
    metadata->checksum = SIGNATURE ^ metadata->size;
  }
  else
  {
    /* Verify metadata integrity */
    if (metadata->checksum != (metadata->sign ^ metadata->size))
    {
      TRACE("Metadata integrity issue");
      return NULL;
    }
    scm->memory_in_use = metadata->size;
  }

  return scm;
}

/* Closes the shared memory and releases resources */
void scm_close(struct scm *scm)
{
  if (scm->mem)
  {
    /* Update metadata before closing */
    struct initmem *metadata = (struct initmem *)scm->mem;
    metadata->size = scm->memory_in_use;
    metadata->sign = SIGNATURE;
    metadata->checksum = SIGNATURE ^ metadata->size;
     if (msync(scm->mem, scm->available_memory, MS_SYNC) == -1) {
        TRACE("msync failed");
    }
    if (munmap(scm->mem, scm->available_memory) == -1) {
        TRACE("munmap failed");
    }
    if (close(scm->fd) == -1) {
        TRACE("close failed");
    }
    free(scm);
  }
}

/* Allocates memory within the shared memory region */
void *scm_malloc(struct scm *scm, size_t N)
{
  void *ptr;

  /* Check if there is enough available memory */
  if ((scm->memory_in_use + N) > scm->available_memory)
  {
    TRACE("Not Enough Memory for Allocation.");
    return NULL;
  }

  /* Allocate memory and update usage */
  ptr = (uint8_t *)scm_mbase(scm) + scm->memory_in_use;
  scm->memory_in_use += N;
  return ptr;
}

/* Duplicates a string within the shared memory */
char *scm_strdup(struct scm *scm, const char *s)
{
  size_t n = strlen(s) + 1;
  char *p;

  /* Allocate space for the string */
  p = scm_malloc(scm, n);
  if (!p)
  {
    TRACE("Failed to allocate memory for string duplication");
    return NULL;
  }

  /* Copy the string into allocated memory */
  memcpy(p, s, n);
  return p;
}

/* Stub for freeing memory within shared memory */
void scm_free(struct scm *scm, void *p)
{
  UNUSED(scm);
  UNUSED(p);
  /* STUB */
}

/* Returns the amount of utilized memory */
size_t scm_utilized(const struct scm *scm)
{
  return scm->memory_in_use;
}

/* Returns the remaining capacity in shared memory */
size_t scm_capacity(const struct scm *scm)
{
  return scm->available_memory - scm->memory_in_use;
}

/* Returns the base address of the allocated memory */
void *scm_mbase(struct scm *scm)
{
  return (char *)scm->mem + sizeof(struct initmem);
}
