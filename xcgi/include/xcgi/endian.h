#pragma once

#include <stdint.h>
#include <string.h>

#if defined (__GLIBC__)
# include <endian.h>
# if (__BYTE_ORDER == __LITTLE_ENDIAN)
#  define LITTLE_ENDIAN
# elif (__BYTE_ORDER == __BIG_ENDIAN)
#  define BIG_ENDIAN
#  error Unknown machine endianness detected.
# endif
# define BYTE_ORDER __BYTE_ORDER
#elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
# define BIG_ENDIAN
# define BYTE_ORDER 4321
#elif defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
# define LITTLE_ENDIAN
# define BYTE_ORDER 1234
#elif defined(__sparc) || defined(__sparc__) \
   || defined(_POWER) || defined(__powerpc__) \
   || defined(__ppc__) || defined(__hpux) || defined(__hppa) \
   || defined(_MIPSEB) || defined(_POWER) \
   || defined(__s390__)
# define BIG_ENDIAN
# define BYTE_ORDER 4321
#elif defined(__i386__) || defined(__alpha__) \
   || defined(__ia64) || defined(__ia64__) \
   || defined(_M_IX86) || defined(_M_IA64) \
   || defined(_M_ALPHA) || defined(__amd64) \
   || defined(__amd64__) || defined(_M_AMD64) \
   || defined(__x86_64) || defined(__x86_64__) \
   || defined(_M_X64) || defined(__bfin__)
# define LITTLE_ENDIAN
# define BYTE_ORDER 1234
#else
# error The file endian.h needs to be set up for your CPU type.
#endif

#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

static inline uint16_t byte_swap16(uint16_t x) {
#if (__GNUC__ > 4 ||(__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) || __has_builtin(__builtin_bswap16)
    return __builtin_bswap16(x);
#else
    return (x << 8) | (x >> 8);
#endif
}

static inline uint32_t byte_swap32(uint32_t x) {
#if (__GNUC__ > 4 ||(__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) || __has_builtin(__builtin_bswap32)
	  return __builtin_bswap32(x);
#else
	  x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0x00FF00FF);
	  return (x << 16) | (x >> 16);
#endif
}

static inline uint64_t byte_swap64(uint64_t x) {
#if (__GNUC__ > 4 ||(__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) || __has_builtin(__builtin_bswap64)
    return __builtin_bswap64(x);
#else
    return ((uint64_t)byte_swap32(x) << 32 | byte_swap32(x >> 32));
#endif
}

#if defined(BIG_ENDIAN)

#define cpu_to_be16(x) ((uint16_t)x)
#define cpu_to_be32(x) ((uint32_t)x)
#define cpu_to_be64(x) ((uint64_t)x)

#define cpu_to_le16(x) byte_swap16(x)
#define cpu_to_le32(x) byte_swap32(x)
#define cpu_to_le64(x) byte_swap64(x)

#define be_to_cpu16(x) ((uint16_t)x)
#define be_to_cpu32(x) ((uint32_t)x)
#define be_to_cpu64(x) ((uint64_t)x)

#define le_to_cpu16(x) byte_swap16(x)
#define le_to_cpu32(x) byte_swap32(x)
#define le_to_cpu64(x) byte_swap64(x)

#elif defined(LITTLE_ENDIAN)

#define cpu_to_be16(x) byte_swap16(x)
#define cpu_to_be32(x) byte_swap32(x)
#define cpu_to_be64(x) byte_swap64(x)

#define cpu_to_le16(x) ((uint16_t)x)
#define cpu_to_le32(x) ((uint32_t)x)
#define cpu_to_le64(x) ((uint64_t)x)

#define be_to_cpu16(x) byte_swap16(x)
#define be_to_cpu32(x) byte_swap32(x)
#define be_to_cpu64(x) byte_swap64(x)

#define le_to_cpu16(x) ((uint16_t)x)
#define le_to_cpu32(x) ((uint32_t)x)
#define le_to_cpu64(x) ((uint64_t)x)

#endif

static inline void encode_be16(void *p, uint16_t x) {
    uint16_t tmp = cpu_to_be16(x);
    memcpy(p, &tmp, sizeof(tmp));
}

static inline void encode_be32(void *p, uint32_t x) {
    uint32_t tmp = cpu_to_be32(x);
    memcpy(p, &tmp, sizeof(tmp));
}

static inline void encode_be64(void *p, uint64_t x) {
    uint64_t tmp = cpu_to_be64(x);
    memcpy(p, &tmp, sizeof(tmp));
}

static inline uint16_t decode_be16(void* p) {
    uint16_t tmp = 0;
    memcpy(&tmp, p, sizeof(tmp));
    return be_to_cpu16(tmp);
}

static inline uint32_t decode_be32(void* p) {
    uint32_t tmp = 0;
    memcpy(&tmp, p, sizeof(tmp));
    return be_to_cpu32(tmp);
}

static inline uint64_t decode_be64(void* p) {
    uint64_t tmp = 0;
    memcpy(&tmp, p, sizeof(tmp));
    return be_to_cpu64(tmp);
}