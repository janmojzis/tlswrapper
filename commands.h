#ifndef COMMANDS_H
#define COMMANDS_H

#include "sio.h"

struct commands {
  char *verb;
  long long (*action)(char *, char *);
  void (*flush)(void);
};

extern int commands(sio *, struct commands *);

#endif
