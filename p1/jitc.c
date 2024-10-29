/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * jitc.c
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dlfcn.h>
#include "system.h"
#include "jitc.h"

struct jitc {
  void* handle;
};

/**
 * Compiles a C program into a dynamically loadable module.
 *
 * input : the file pathname of the C program
 * output: the file pathname of the dynamically loadable module
 *
 * return: 0 on success, otherwise error
 */

int jitc_compile(const char *input, const char *output) {
  int pid = fork();
  int status = 0;
  int i = 0;
  waitpid(pid, &status, 0);
  if (pid < 0) {
      TRACE("pid < 0 - fork()");
      return -1;
  } else if (pid == 0) {
      char *exec_program = "/usr/bin/gcc";
      char *exec_args[7];
      exec_args[0] = exec_program;
      exec_args[1] = "-o";
      exec_args[2] = (char*) output;
      exec_args[3] = (char*) input;
      exec_args[4] = "-fpic";
      exec_args[5] = "-shared";
      exec_args[6] = NULL;
      execv(exec_program, exec_args);
      for (; i < 7; ++i) {
        free(exec_args[i]);
    }
  }
  if(WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    return 0;
  } else {
    return -1;
  }
}

/**
 * Loads a dynamically loadable module into the calling process' memory for
 * execution.
 *
 * pathname: the file pathname of the dynamically loadable module
 *
 * return: an opaque handle or NULL on error
 */

struct jitc *jitc_open(const char *pathname) {
  struct jitc* jitc = malloc(sizeof(struct jitc));

  char *path;
  if((path = malloc(strlen("./")+strlen(pathname)+1)) != NULL){
    path[0] = '\0'; /* https://stackoverflow.com/questions/5901181/c-string-append */
    strcat(path, "./");
    strcat(path, pathname);
  } else {
    fprintf(stderr,"Setting path name failed!\n");
    free(path);
    exit(1);
  }

  dlerror();
  jitc->handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
  if (!jitc->handle) {
    const char *error = dlerror();
    if (error) {
      fprintf(stderr, "Error in jitc_open: %s\n\n", error);
      free(path);
      exit(1);
    }
  }

  free(path);
  return jitc;
}

/**
 * Unloads a previously loaded dynamically loadable module.
 *
 * jitc: an opaque handle previously obtained by calling jitc_open()
 *
 * Note: jitc may be NULL
 */

void jitc_close(struct jitc *jitc) {
     if(jitc->handle) {
      int status = dlclose(jitc->handle);
      if (status != 0) {
        fprintf(stderr, "Error in dlclose: %s\n\n", dlerror());
      }
}
     FREE(jitc);
}


/**
 * Searches for a symbol in the dynamically loaded module associated with jitc.
 *
 * jitc: an opaque handle previously obtained by calling jitc_open()
 *
 * return: the memory address of the start of the symbol, or 0 on error
 */

long jitc_lookup(struct jitc *jitc, const char *symbol) {
  void *sym;
  if(!jitc || !jitc->handle) {
    return 0;
  }

  sym = dlsym(jitc->handle, symbol);
  return (long)sym;
}

/**
 * Needs:
 *   fork()
 *   execv()
 *   waitpid()
 *   WIFEXITED()
 *   WEXITSTATUS()
 *   dlopen()
 *   dlclose()
 *   dlsym()
 */

/* research the above Needed API and design accordingly */
