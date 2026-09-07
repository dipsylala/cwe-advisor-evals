/* Force-included (-include) by scripts/parsecheck.py for gcc/clang syntax checks; the
   counterpart of msvc_compat.h. glibc stops declaring gets() from C11 on and clang 16+ makes a
   call to an undeclared function an error, so the CWE-121 fixture whose sink is gets() would
   fail to compile for the reason it exists. Declare it: where glibc still declares it (-std=gnu99,
   _GNU_SOURCE) a second declaration with the same type is legal C. C only; not used for C++. */
#include <stdio.h>
char *gets(char *);
