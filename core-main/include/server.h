#ifndef SERVER_H
#define SERVER_H

#include <pthread.h>

typedef struct {
  int task_id;
  char type[32];
  char target[256];
  int is_running;
} ctf_task_it;

void start_server(int_port);

void* tool_potok(void* arg);

#endif
