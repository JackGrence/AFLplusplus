#include "visualizer.h"
#include <unistd.h>
#include <stdlib.h>

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

static void visualizer_http_recv(int fd, char *buf, int len) {

  int offset;
  while ((offset = read(fd, buf, len)) > 0) {
      buf += offset;
      len -= offset;
  }

  if (offset < 0) { VISFATAL("HTTP recv fail"); }

}

static void visualizer_request_get(char *request, char *buf, size_t size) {

  int http_fd;
  char *ptr;
  size_t len;
  http_fd = visualizer_http_fd();
  len = write(http_fd, request, strlen(request));
  if (len == strlen(request)) {

    bzero(buf, size);
    visualizer_http_recv(http_fd, buf, size - 1);
    close(http_fd);
    ptr = strstr(buf, "\r\n\r\n");
    if (ptr != NULL) {

      ptr += 4;
      strcpy(buf, ptr);

    }

  }

}

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

void visualizer_prepare_seed(u8 *queue_fn) {

  int http_fd;
  char *data = "GET /seed?fn=%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char *buf = "";
  char seedpath[PATH_MAX];
  u32 len;

  buf = realpath(queue_fn, seedpath);
  if (buf == NULL) { FATAL("Seed path resolve fail"); }
  http_fd = visualizer_http_fd();
  buf = alloc_printf(data, seedpath);
  len = write(http_fd, buf, strlen(buf));
  if (len != strlen(buf)) { FATAL("HTTP request fail"); }
  ck_free(buf);
  close(http_fd);

}
