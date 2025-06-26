
#include "Python.h"

#ifndef PLATFORM
#define PLATFORM "unknown"
#endif

const char *
Py_GetPlatform(void)
{
	return PLATFORM;
}

#ifndef ARCH
#define ARCH "unknown"
#endif

const char *
Py_GetArch(void)
{
	return ARCH;
}

#ifndef LIB
#define LIB "lib"
#endif

const char *
Py_GetLib(void)
{
	return LIB;
}
