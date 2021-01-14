#include "visualizer.h"
#include <unistd.h>


static void visualizer_get_state(afl_state_t *afl, vis_config_t *conf) {

  u8 *fn;
  u8 *buf;
  u32 len;
  u32 fd;
  struct stat st;

  fn = conf->seeds[0];

  if (lstat(fn, &st) || access(fn, R_OK)) {

    PFATAL("Unable to access '%s'", fn);

  }

  fd = open(fn, O_RDONLY);

  if (unlikely(fd < 0)) {

    PFATAL("Unable to open '%s'", fn);

  }

  len = st.st_size;

  buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  write_to_testcase(afl, buf, len);

  // inform forkserver to read config
  kill(afl->fsrv.fsrv_pid, SIGUSR2);
  u8 fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  munmap(buf, len);

}

void visualizer_afl(afl_state_t *afl) {

  vis_config_t *conf;
  conf = visualizer_get_config(afl);
  if (conf) {

    switch (conf->action) {

      case VIS_GET_STATE:
	visualizer_get_state(afl, conf);
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
