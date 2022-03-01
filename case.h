#ifndef _CASE_H____
#define _CASE_H____

extern int case_diffb(const char *, long long, const char *);
extern int case_diffs(const char *, const char *);
extern int case_startb(const char *, long long, const char *);
extern int case_starts(const char *, const char *);
extern void case_lowerb(char *, long long);
extern void case_lowers(char *);
#define case_equals(s, t) (!case_diffs((s), (t)))
#define case_equalb(s, t, len) (!case_diffb((s), (t), (len)))

#endif
