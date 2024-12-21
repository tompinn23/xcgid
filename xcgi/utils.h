#pragma once

#include <stddef.h>

char *xstrndup(const char *s, size_t n);

int xfullread(int fd, int eof, void *buffer, size_t bufsize);
int xfullwrite(int fd, const void *s, size_t n);

int xreaddiscard(int fd, size_t bufsize);