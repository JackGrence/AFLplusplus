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
  // TODO: afl config
  web_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  web_addr.sin_port = htons(5000);

  if (connect(http_fd, (struct sockaddr *) &web_addr, sizeof(web_addr)) != 0) {
    close(http_fd);
    PFATAL("connect");
  }

  return http_fd;
}

vis_config_t *visualizer_get_config(afl_state_t *afl) {

  int http_fd;
  char *data = "GET /fuzzer HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char buf[0x400];
  char *ptr;
  u32 len, offset, i;
  vis_config_t *conf;
  http_fd = visualizer_http_fd(afl);
  len = write(http_fd, data, strlen(data));
  if (len == strlen(data)) {

    bzero(buf, sizeof(buf));
    len = read(http_fd, buf, 0x3ff);
    if (len > 0) {

      ptr = strstr(buf, "\r\n\r\n");
      if (ptr != NULL) {

	ptr += 4;
	conf = ck_alloc(sizeof(*conf));
	len = sscanf(ptr, "%d%Lx%d%n", (int *) &conf->action, &conf->addr, &conf->value_num, &offset);
	if (len == 3) {

	  ptr += offset;
	  conf->values = ck_alloc(sizeof(vis_value_t) * conf->value_num);
	  for (i = 0; i < conf->value_num; ++i) {

	    len = sscanf(ptr, "%19s%Lx%n", conf->values[i].reg, &conf->values[i].value, &offset);
	    if (len != 2) { break; }
	    ptr += offset;

	  }
	  if (len == 2) {

	    close(http_fd);
	    return conf;

	  }

	  ck_free(conf->values);

	}

	ck_free(conf);

      }

    }

  }

  close(http_fd);
  FATAL("HTTP request fail");
  return NULL;

}

static void visualizer_get_state(afl_state_t *afl) {

  // inform forkserver to read config
  kill(afl->fsrv.fsrv_pid, SIGUSR2);
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

    ck_free(conf->values);
    ck_free(conf);

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
