#include "visualizer.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

static int visualizer_http_fd(afl_state_t *afl) {

  int http_fd;
  struct sockaddr_in web_addr;

  http_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (http_fd == -1) { PFATAL("socket"); }
  bzero(&web_addr, sizeof(web_addr));

  web_addr.sin_family = AF_INET;
  web_addr.sin_addr.s_addr = inet_addr(afl->visualizer_host);
  web_addr.sin_port = htons(afl->visualizer_port);

  if (connect(http_fd, (struct sockaddr *) &web_addr, sizeof(web_addr)) != 0) {
    close(http_fd);
    PFATAL("connect");
  }

  return http_fd;
}

vis_config_t *visualizer_alloc_config(char *str) {

 /* "0 0x197d0 2 ./afl_inputs/vlanIntfs
  * ./afl_inputs/vlan 2 r1 0 0x197d0 0x4141" */

  vis_config_t *conf;
  u32 offset, i;

  // TODO: sscanf check
  conf = ck_alloc(sizeof(*conf));
  sscanf(str, "%d%Lx%d%n", (int *) &conf->action,
	 &conf->addr, &conf->seed_num, &offset);
  str += offset;

  // parse seed
  conf->seeds = ck_alloc(sizeof(char *) * conf->seed_num);
  for (i = 0; i < conf->seed_num; ++i) {
    conf->seeds[i] = ck_alloc(0x100);
    sscanf(str, "%255s%n", conf->seeds[i], &offset);
    str += offset;
  }

  // parse value
  sscanf(str, "%d%n", &conf->value_num, &offset);
  str += offset;
  conf->values = ck_alloc(sizeof(vis_value_t) * conf->value_num);
  for (i = 0; i < conf->value_num; ++i) {

    sscanf(str, "%19s%Lx%n", conf->values[i].reg,
	   &conf->values[i].value, &offset);
    str += offset;

  }

  return conf;

}

void visualizer_free_config(vis_config_t *config) {

  u32 i;
  for (i = 0; i < config->seed_num; ++i) {
    ck_free(config->seeds[i]);
  }
  ck_free(config->seeds);
  ck_free(config->values);
  ck_free(config);

}

static void visualizer_http_recv(int fd, char *buf, int len) {

  int offset;
  while ((offset = read(fd, buf, len)) > 0) {
      buf += offset;
      len -= offset;
  }

  if (offset < 0) { FATAL("HTTP recv fail"); }

}

vis_config_t *visualizer_get_config(afl_state_t *afl) {

  int http_fd;
  char *data = "GET /fuzzer HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char buf[0x400];
  char *ptr;
  u32 len;
  vis_config_t *conf;
  http_fd = visualizer_http_fd(afl);
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
  FATAL("HTTP request fail");
  return NULL;

}

static void visualizer_get_state(afl_state_t *afl) {

  // inform forkserver to read config
  // kill(afl->fsrv.fsrv_pid, SIGUSR2);
  afl->visualizer_port = afl->visualizer_port;
  // choose target seed

}

void visualizer_afl(afl_state_t *afl) {

  vis_config_t *conf;
  conf = visualizer_get_config(afl);
  if (!conf) {

    switch (conf->action) {

      case VIS_GET_STATE:
	visualizer_get_state(afl);
	break;

      case VIS_GET_RELATION:
	break;

      case VIS_SET_CONSTRAINT:
	break;

      default:
	break;

    }

    visualizer_free_config(conf);

  }

}

void visualizer_prepare_seed(afl_state_t *afl, u8 *queue_fn) {

  int http_fd;
  char *data = "GET /seed?fn=%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char *buf = "";
  u32 len;

  http_fd = visualizer_http_fd(afl);
  buf = alloc_printf(data, queue_fn);
  len = write(http_fd, buf, strlen(buf));
  if (len != strlen(buf)) { FATAL("HTTP request fail"); }
  ck_free(buf);
  close(http_fd);

}
