#ifndef ALLOC_H____
#define ALLOC_H____

#define alloc_VERSION "20260416"

#ifndef alloc_ALIGNMENT
#define alloc_ALIGNMENT (4 * sizeof(unsigned long))
#endif
#ifndef alloc_STATICSPACE
#define alloc_STATICSPACE (4096 * alloc_ALIGNMENT)
#endif
#ifndef alloc_MAX
#define alloc_MAX (((unsigned long long) (-1)) >> 1)
#endif

extern void *alloc(long long);
extern void alloc_free(void *);
extern void alloc_freeall(void);

#endif
