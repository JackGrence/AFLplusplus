#ifndef _AFL_VISUALIZER_H
#define _AFL_VISUALIZER_H

#include "afl-fuzz.h"
#include "config.h"
#include "list.h"
#include "types.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct vis_constraint {

  u32 offset;
  u32 length;
  u8  *data;

} vis_constraint_t;

void visualizer_constraints_get(afl_state_t *afl);
void visualizer_constraints_set(afl_state_t *afl, u8 *buf, u32 size);
void visualizer_afl(afl_state_t *afl);
void visualizer_prepare_seed(u8 *queue_fn);

#define VISFATAL(x) { puts(x); abort(); }
#define VISPFATAL(x) { perror(x); abort(); }
#define HEADER_GET(url) ("GET " url " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
#define VIS_REQUEST_GET(url, buf, size)			\
  do {							\
							\
    visualizer_request_get(HEADER_GET(url), buf, size); \
							\
  } while(0)

#endif /* ifndef _AFL_VISUALIZE_H */
