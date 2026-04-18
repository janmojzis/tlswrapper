#ifndef ALLOC_H____
#define ALLOC_H____

#define alloc_VERSION "20260417"

#ifndef alloc_ALIGNMENT
#define alloc_ALIGNMENT (4 * sizeof(unsigned long))
#endif
#ifndef alloc_STATICSPACE
#define alloc_STATICSPACE (4096 * alloc_ALIGNMENT)
#endif

extern void *alloc(long long);
extern void alloc_limit(long long);
extern void alloc_free(void *);
extern void alloc_freeall(void);

#endif
