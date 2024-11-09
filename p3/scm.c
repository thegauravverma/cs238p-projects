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

<<<<<<< Updated upstream
=======
/* Metadata structure for tracking freeblocks */
struct memblock
{
  uint8_t size; /* Size for the block */
  uint8_t used; /* 1 if in use, 0 if not */
};

/* Sets the file size and updates available memory in scm */
>>>>>>> Stashed changes
void set_file_size(struct scm *scm)
{
  /* Check that the file's open */
  struct stat st;
<<<<<<< Updated upstream
  if (fstat(scm->fd, &st) == -1)
  {
    TRACE("Failed to stat file");
=======

  /* Check if file is open */
  if (fstat(scm->fd, &st) == -1)
  {
    TRACE("Failed to open file");
>>>>>>> Stashed changes
    exit(EXIT_FAILURE); /* Exit if fstat fails */
  }

  if (!S_ISREG(st.st_mode))
  {
    TRACE("Error: Not a regular file");
    exit(EXIT_FAILURE);
  }
<<<<<<< Updated upstream
=======

  /* Align the file size and set available memory */
>>>>>>> Stashed changes
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
    exit(EXIT_FAILURE);
  };

  scm->fd = open(pathname, O_RDWR);
  if (!scm->fd)
  {
    TRACE("Failed to open file");
    free(scm);
    exit(EXIT_FAILURE);
  }

  set_file_size(scm);     /* Set the file size and available memory in scm */
  curr = (size_t)sbrk(0); /* Gets the current breakline */
  vm_addr = descriptor_align(VM_ADDR);
  if (truncate)
  {
    if (ftruncate(scm->fd, (long)scm->available_memory) == -1)
    {
      TRACE("Failed to truncate file");
      close(scm->fd);
      free(scm);
      exit(EXIT_FAILURE);
    };
  }
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

  /* Size and sign initialization */
  metadata = (struct initmem *)scm->mem;
  if (!metadata)
  {
    TRACE("Error: Failed to access metadata");
    scm_close(scm);
    return NULL;
  }
  if (truncate || metadata->sign != SIGNATURE || metadata->checksum != (SIGNATURE ^ metadata->size))
  {
    metadata->sign = SIGNATURE;
    metadata->size = 0;
    metadata->checksum = SIGNATURE ^ metadata->size;
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
  if (scm->mem)
  {
    struct initmem *metadata = (struct initmem *)scm->mem;
    metadata->size = scm->memory_in_use;
    metadata->sign = SIGNATURE;
    metadata->checksum = SIGNATURE ^ metadata->size;
<<<<<<< Updated upstream
    msync(scm->mem, scm->available_memory, MS_SYNC);
    munmap(scm->mem, scm->available_memory);
=======
    if (msync(scm->mem, scm->available_memory, MS_SYNC) == -1)
    {
      TRACE("msync failed");
    }
    if (munmap(scm->mem, scm->available_memory) == -1)
    {
      TRACE("munmap failed");
    }
    if (close(scm->fd) == -1)
    {
      TRACE("close failed");
    }
    free(scm);
>>>>>>> Stashed changes
  }
  if (scm->fd)
  {
    close(scm->fd);
  }
  free(scm);
}

void *check_free_list(struct scm *scm, size_t N)
{
  UNUSED(scm);
  UNUSED(N);

  return NULL;
}

<<<<<<< Updated upstream
=======
/* Finds a free block if one exists */
void *get_free_block(struct scm *scm, size_t N)
{
  struct memblock *meta;

  TRACE("Trying to get the ptr");

  meta = (struct memblock *)((char *)scm_mbase(scm) - sizeof(struct memblock));
  while (1)
  {
    if ((meta->size >= N) && (meta->used == 0))
    {
      meta->used = 1;

      TRACE("Found one!");
      return (void *)((char *)meta + sizeof(struct memblock));
    }

    /* If we can't find another chunk of memory after this one that has enough space to store both a memblock */
    /* and the space we need, we need to exit out; We're truly out of luck. */
    TRACE("Doing the beegmath");
    if ((char *)meta + sizeof(struct memblock) + meta->size + sizeof(struct memblock) + N > (char *)scm->mem + sizeof(struct initmem) + scm->available_memory)
    {
      TRACE("Cannot find freeblock for allocation");
      return NULL;
    }

    TRACE("Iterating ptr");
    meta = (struct memblock *)((char *)meta + sizeof(struct memblock) + meta->size);
  }
}

/* Allocates memory within the shared memory region */
>>>>>>> Stashed changes
void *scm_malloc(struct scm *scm, size_t N)
{
  struct memblock *meta;
  void *ptr;

<<<<<<< Updated upstream
  if ((scm->memory_in_use + N) > scm->available_memory)
  {
    TRACE("Not Enough Memory for Allocation.");
    exit(EXIT_FAILURE);
  }

  TRACE("HERE!");

  ptr = (uint8_t *)scm->mem + scm->memory_in_use;
  scm->memory_in_use += N;

=======
  /* Check if there is enough available memory */
  if ((sizeof(struct initmem) + scm->memory_in_use + N + sizeof(struct memblock)) > scm->available_memory)
  {
    return get_free_block(scm, N);
  }

  /* Allocate memory and update usage */
  meta = (struct memblock *)(((char *)scm_mbase(scm) - sizeof(struct memblock)) + scm->memory_in_use);
  meta->size = N;
  meta->used = 1;

  ptr = (char *)meta + sizeof(struct memblock);
  scm->memory_in_use += N + sizeof(struct memblock);
>>>>>>> Stashed changes
  return ptr;
}

char *scm_strdup(struct scm *scm, const char *s)
{
<<<<<<< Updated upstream
  size_t str_len;
  char *dup_str;
  size_t i;
  if (!s)
=======
  struct memblock *meta;

  size_t n = strlen(s) + 1;
  char *p;

  /* Allocate space for the string */
  p = scm_malloc(scm, n);
  meta = (struct memblock *)((char *)p - sizeof(struct memblock));
  TRACE("Getting strcpy");
  if (!p)
>>>>>>> Stashed changes
  {
    TRACE("Given string is NULL");
    return NULL;
  }
<<<<<<< Updated upstream
  str_len = strlen(s) + 1;
  if (!(dup_str = scm_malloc(scm, str_len)))
  {
    TRACE(0);
    return NULL;
  }
  for (i = 0; i < str_len; i++)
  {
    dup_str[i] = s[i];
  }
  return dup_str;
=======

  printf("%d\n", meta->size);
  printf("%d\n", meta->used);
  printf("%d\n", (int)n);
  printf("%p\n", p);
  printf("%s\n", s);

  /* Copy the string into allocated memory */
  memcpy(p, s, n);
  return p;
>>>>>>> Stashed changes
}

void scm_free(struct scm *scm, void *p)
{
  struct memblock *meta;
  char *ptr;
  int i = 0;

  TRACE("FREEDING");
  meta = (struct memblock *)((char *)p - sizeof(struct memblock));

  meta->used = 0;

  ptr = p;
  for (; i < meta->size; ++i)
  {
    ptr[i] = 0;
  }

  UNUSED(scm);
<<<<<<< Updated upstream
  UNUSED(p);
=======
>>>>>>> Stashed changes

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
<<<<<<< Updated upstream
  return (uint8_t *)scm->mem;
=======
  return (char *)scm->mem + sizeof(struct initmem) + sizeof(struct memblock);
>>>>>>> Stashed changes
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
