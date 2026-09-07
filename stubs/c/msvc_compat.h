/* Force-included (cl /FI) when the C and C++ fixtures are checked with MSVC instead of gcc or
 * clang. The fixtures are POSIX C; this supplies the few POSIX spellings MSVC's headers lack so
 * that a fixture which is correct everywhere CI compiles it is not reported as broken here. Keep
 * it to definitions, never behaviour: the point is to type-check the fixture, not to run it. */
#ifndef CWE_EVALS_MSVC_COMPAT_H
#define CWE_EVALS_MSVC_COMPAT_H
#ifdef _MSC_VER
#include <stddef.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif
#endif
