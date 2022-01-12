#include <strings.h>
#include <string.h>
#include "sio.h"
#include "log.h"
#include "stralloc.h"
#include "commands.h"

static stralloc cmd = {0};

static long long str_chr(const char *str, int c) {

    const char *s;
    char ch = c;

    for (s = str; (*s && *s != ch); ++s)
        ;
    return (s - str);
}

int commands(sio *g, struct commands *c)
{
  long long i, code;
  char *arg;
  char ch;

  for (;;) {
    if (!stralloc_copys(&cmd, "")) return -1;

    for (;;) {
      i = sio_getch(g, &ch);
      if (i != 1) return i;
      if (ch == '\n') break;
      if (!ch) ch = '\n';
      if (!stralloc_append(&cmd,&ch)) return -1;
    }

    if (cmd.len > 0) if (cmd.s[cmd.len - 1] == '\r') --cmd.len;

    if (!stralloc_0(&cmd)) return -1;

    i = str_chr(cmd.s, ' ');
    arg = cmd.s + i;
    while (*arg == ' ') ++arg;
    cmd.s[i] = 0;

    for (i = 0;c[i].verb;++i) if (!strcasecmp(c[i].verb,cmd.s)) break;
    code = c[i].action(cmd.s, arg);
    if (strlen(arg)) {
        log_d5(cmd.s, " ", arg, ": ", lognum(code));
    }
    else {
        log_d3(cmd.s, ": ", lognum(code));
    }
    if (c[i].flush) c[i].flush();
  }
}
