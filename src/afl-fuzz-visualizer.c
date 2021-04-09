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

static u64 seed2rand(constraint_endian_t endian, u8 *buf, u32 size) {

  u64 result = 0;
  u32 i, ind;

  for (i = 0; i < size; i++) {

    ind = i;

    if (endian == ENDIAN_LITTLE)
      ind = size - i - 1;

    result = (result << 8) + buf[ind];

  }

  return result;

}

void visualizer_constraints_set(afl_state_t *afl, u8 *buf, u32 size) {

  u32 ind, byte_ind;
  u32 overwrite_len;
  u64 start, end;
  u64 value;
  u64 seed_value;
  constraint_data_t tmp_data;
  constraint_data_t *choosed_data;

  LIST_FOREACH(&afl->visualizer_constraints_list, vis_constraint_t, {
    // do while to let we break and don't mess the LIST_FOREACH
    do {

      if (el->offset >= size) { break; }
      // init
      bzero(&tmp_data, sizeof(tmp_data));
      choosed_data = &tmp_data;
      // generate index by seed
      overwrite_len = MIN(size - el->offset, el->overwrite_len);
      seed_value = seed2rand(el->endian, &buf[el->offset],
                             MIN(sizeof(seed_value), overwrite_len));
      // choose data
      if (el->constraint_type == CONSTRAINT_RANGE) {
        // TODO: check more logic bug
        if (el->endian == ENDIAN_BYTE) { break; }
        if (el->data_cnt != 2) { break; }

        *choosed_data = *el->data[0];
        start = el->data[0]->data.num64;
        end = el->data[1]->data.num64;
        // break if seed already in range
        if (seed_value >= start && seed_value <= end) { break; }
        choosed_data->data.num64 = (seed_value % (end - start + 1)) + start;

      } else {
        // break if seed already in whitelist
        for (ind = 0; ind < el->data_cnt; ind++) {

          if (!memcmp(buf, el->data[ind]->data.bytes,
                      MIN(el->data[ind]->length, overwrite_len))) { break; }

        }
        // choose data
        if (el->endian != ENDIAN_BYTE) {
          // number will be reorder, so take a copy
          *choosed_data = *el->data[seed_value % el->data_cnt];

        } else {
          // bytes have variant length, so take a reference
          choosed_data = el->data[seed_value % el->data_cnt];

        }

      }
      // modify buf
      if (el->offset < size) {

        value = choosed_data->data.num64;
        // translate value to target endian
        if (el->endian != ENDIAN_BYTE) {

          for (ind = 0; ind < choosed_data->length; ind++) {

            byte_ind = ind;

            if (el->endian == ENDIAN_BIG) {

              byte_ind = choosed_data->length - 1 - ind;

            }
            // there is a copy of number, modify it is fine
            choosed_data->data.bytes[byte_ind] = value & 0xff;
            value >>= 8;

          }

        }
        // TODO: insert data.length - overwrite_len to buf.
        //       but may be a bad idea.
        memcpy(&buf[el->offset], choosed_data->data.bytes,
               MIN(choosed_data->length, overwrite_len));
      }

    } while (0);

  });

}

void visualizer_constraints_get(afl_state_t *afl) {

  char buf[0x400];
  char *ptr = buf;
  u32 offset, size;
  u32 con_cnt, data_cnt, byte_cnt;
  u64 value;
  vis_constraint_t constraint_tmp;
  vis_constraint_t *constraint_ptr;
  constraint_data_t *data;

  if (afl->visualizer_constraints_count) {

    // clear old constraint
    LIST_FOREACH_CLEAR(&afl->visualizer_constraints_list, vis_constraint_t, {
      for (data_cnt = 0; data_cnt < el->data_cnt; data_cnt++) {
        ck_free(el->data[data_cnt]);
      }
      ck_free(el);
    });
    afl->visualizer_constraints_count = 0;

  }

  // parse constraint
  VIS_REQUEST_GET("/fuzzer", buf, 0x400);
  sscanf(ptr, "%d%n", &afl->visualizer_constraints_count, &offset);
  ptr += offset;
  for (con_cnt = 0; con_cnt < afl->visualizer_constraints_count; con_cnt++) {
    constraint_ptr = &constraint_tmp;
    sscanf(ptr, "%d%d%d%d%d%n",
           (int *) &constraint_ptr->constraint_type,
           (int *) &constraint_ptr->endian,
           &constraint_ptr->offset,
           &constraint_ptr->overwrite_len,
           &constraint_ptr->data_cnt,
           &offset);
    ptr += offset;
    // calc constraint size then malloc
    size = sizeof(*constraint_ptr);
    size += sizeof(void *) * constraint_ptr->data_cnt;
    constraint_ptr = ck_alloc(size);
    // copy back
    *constraint_ptr = constraint_tmp;
    // parse data
    for (data_cnt = 0; data_cnt < constraint_ptr->data_cnt; data_cnt++) {

      sscanf(ptr, "%d%n", &size, &offset);
      ptr += offset;
      // I'm lazy to calculate the accurate size, just add it :3
      data = ck_alloc(sizeof(*data) + size);
      constraint_ptr->data[data_cnt] = data;
      data->length = size;
      // init data.num
      memset(data->data.bytes, 0, 8);
      // read bytes to constraint_data
      for (byte_cnt = 0; byte_cnt < size; byte_cnt++) {

        sscanf(ptr, "%hhx%n", &data->data.bytes[byte_cnt], &offset);
        ptr += offset;

      }
      // translate network order to host order, ignore odd number now
      if (constraint_ptr->endian != ENDIAN_BYTE) {

        value = 0;
        if (data->length == 8) {

          value = ntohl(*(u32 *) data->data.bytes);
          value = (value << 32) + ntohl(*(u32 *) &data->data.bytes[4]);

        } else if (data->length == 4) {

          value = ntohl(*(u32 *) data->data.bytes);

        } else if (data->length == 2) {

          value = ntohs(*(u16 *) data->data.bytes);

        } else {

          // ensure data->length in 1, 2, 4, 8
          data->length = 1;
          value = data->data.num8;

        }

        data->data.num64 = value;

      }

    }

    list_append(&afl->visualizer_constraints_list, constraint_ptr);

  }

}

void visualizer_prepare_seed(u8 *queue_fn) {

  int http_fd;
  char *data = "GET /seed?fn=%s&pid=%d HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char *buf = "";
  char seedpath[PATH_MAX];
  u32 len;
  pid_t pid;

  pid = getpid();
  buf = realpath(queue_fn, seedpath);
  if (buf == NULL) { FATAL("Seed path resolve fail"); }
  http_fd = visualizer_http_fd();
  buf = alloc_printf(data, seedpath, pid);
  len = write(http_fd, buf, strlen(buf));
  if (len != strlen(buf)) { FATAL("HTTP request fail"); }
  ck_free(buf);
  close(http_fd);

}
