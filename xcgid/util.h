#pragma once
#include <stdarg.h>

char *xaprintf(const char *fmt, ...);
char *xvaprintf(const char *fmt, va_list va);