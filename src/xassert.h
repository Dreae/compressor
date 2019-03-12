#pragma once

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define xassert(expr)							\
    if (!(expr)) {						\
        fprintf(stderr, "%s:%s:%i: Assertion failed: "	\
            #expr ": errno: %d/\"%s\"\n",		\
            __FILE__, __func__, __LINE__,		\
            errno, strerror(errno));		\
        exit(EXIT_FAILURE);				\
    }							\

