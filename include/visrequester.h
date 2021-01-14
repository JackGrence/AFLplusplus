#ifndef _AFL_VISREQUESTER_H
#define _AFL_VISREQUESTER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "types.h"

#define VISFATAL(x) { puts(x); abort(); }
#define VISPFATAL(x) { perror(x); abort(); }

typedef enum vis_action {

  VIS_GET_STATE = 0,
  VIS_GET_RELATION,
  VIS_SET_CONSTRAINT

} vis_action_t;

typedef struct vis_value {

  char reg[20];
  u64 mem;
  u32 len;
  u64 value;

} vis_value_t;

typedef struct vis_config {

  vis_action_t action;
  u64 addr;
  u32 seed_num;
  char **seeds;
  u32 value_num;
  vis_value_t *values;

} vis_config_t;

static int visualizer_http_fd() {

  int http_fd;
  struct sockaddr_in web_addr;

  http_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (http_fd == -1) { VISPFATAL("socket"); }
  bzero(&web_addr, sizeof(web_addr));

  web_addr.sin_family = AF_INET;
  web_addr.sin_addr.s_addr = inet_addr(getenv("AFL_VISHOST"));
  web_addr.sin_port = htons(atoi(getenv("AFL_VISPORT")));

  if (connect(http_fd, (struct sockaddr *) &web_addr, sizeof(web_addr)) != 0) {
    close(http_fd);
    VISPFATAL("connect");
  }

  return http_fd;
}

static vis_config_t *visualizer_alloc_config(char *str) {

 /* "0 0x197d0 2 ./afl_inputs/vlanIntfs
  * ./afl_inputs/vlan 2 r1 0 0x197d0 0x4141" */

  vis_config_t *conf;
  u32 offset, i;

  // TODO: sscanf check
  conf = malloc(sizeof(*conf));
  sscanf(str, "%d%Lx%d%n", (int *) &conf->action,
	 &conf->addr, &conf->seed_num, &offset);
  str += offset;

  // parse seed
  conf->seeds = malloc(sizeof(char *) * conf->seed_num);
  for (i = 0; i < conf->seed_num; ++i) {
    conf->seeds[i] = malloc(0x100);
    sscanf(str, "%255s%n", conf->seeds[i], &offset);
    str += offset;
  }

  // parse value
  sscanf(str, "%d%n", &conf->value_num, &offset);
  str += offset;
  conf->values = malloc(sizeof(vis_value_t) * conf->value_num);
  for (i = 0; i < conf->value_num; ++i) {

    sscanf(str, "%19s%Lx%n", conf->values[i].reg,
	   &conf->values[i].value, &offset);
    str += offset;

  }

  return conf;

}

static inline void visualizer_free_config(vis_config_t *config) {

  u32 i;
  for (i = 0; i < config->seed_num; ++i) {
    free(config->seeds[i]);
  }
  free(config->seeds);
  free(config->values);
  free(config);

}

static void visualizer_http_recv(int fd, char *buf, int len) {

  int offset;
  while ((offset = read(fd, buf, len)) > 0) {
      buf += offset;
      len -= offset;
  }

  if (offset < 0) { VISFATAL("HTTP recv fail"); }

}

static inline vis_config_t *visualizer_get_config() {

  int http_fd;
  char *data = "GET /fuzzer HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char buf[0x400];
  char *ptr;
  u32 len;
  vis_config_t *conf;
  http_fd = visualizer_http_fd();
  len = write(http_fd, data, strlen(data));
  if (len == strlen(data)) {

    bzero(buf, sizeof(buf));
    visualizer_http_recv(http_fd, buf, 0x3ff);

    ptr = strstr(buf, "\r\n\r\n");
    if (ptr != NULL) {

      ptr += 4;
      conf = visualizer_alloc_config(ptr);
      close(http_fd);
      return conf;

    }

  }

  close(http_fd);
  VISFATAL("HTTP request fail");
  return NULL;

}

#endif
