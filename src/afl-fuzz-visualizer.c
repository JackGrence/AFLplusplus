#include "visualizer.h"
#include <unistd.h>
#include <stdlib.h>


void visualizer_constraints_set(afl_state_t *afl, u8 *buf, u32 size) {

  LIST_FOREACH(&afl->visualizer_constraints_list, vis_constraint_t, {

    if (el->offset < size)
      memcpy(&buf[el->offset], el->data,
	     MIN(size - el->offset, el->length));

  });

}

void visualizer_constraints_get(afl_state_t *afl) {

  char buf[0x400];
  char *ptr = buf;
  u32 offset;
  u32 i, ind;
  vis_constraint_t *constraint;

  if (afl->visualizer_constraints_count) {

    // clear old constraint
    LIST_FOREACH_CLEAR(&afl->visualizer_constraints_list, vis_constraint_t, {
      ck_free(el->data);
      ck_free(el);
    });
    afl->visualizer_constraints_count = 0;

  }

  // parse constraint
  VIS_REQUEST_GET("/fuzzer", buf, 0x400);
  sscanf(ptr, "%d%n", &afl->visualizer_constraints_count, &offset);
  ptr += offset;
  for (i = 0; i < afl->visualizer_constraints_count; i++) {
    constraint = ck_alloc(sizeof(vis_constraint_t));
    sscanf(ptr, "%d%d%n", &constraint->offset, &constraint->length, &offset);
    ptr += offset;
    constraint->data = ck_alloc(constraint->length);
    for (ind = 0; ind < constraint->length; ind++) {
      sscanf(ptr, "%hhx%n", &constraint->data[ind], &offset);
      ptr += offset;
    }
    list_append(&afl->visualizer_constraints_list, constraint);
  }

}

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
  kill(afl->fsrv.fsrv_pid, SIGUSR2);

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
  char seedpath[PATH_MAX];
  u32 len;

  buf = realpath(queue_fn, seedpath);
  if (buf == NULL) { FATAL("Seed path resolve fail"); }
  http_fd = visualizer_http_fd(afl);
  buf = alloc_printf(data, seedpath);
  len = write(http_fd, buf, strlen(buf));
  if (len != strlen(buf)) { FATAL("HTTP request fail"); }
  ck_free(buf);
  close(http_fd);

}
