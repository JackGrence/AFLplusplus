#ifndef _AFL_VISUALIZER_H
#define _AFL_VISUALIZER_H

#include "config.h"
#include "types.h"
#include "afl-fuzz.h"

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
  u32 value_num;
  vis_value_t *values;

} vis_config_t;

void visualizer_afl(afl_state_t *afl);
void visualizer_prepare_seed(afl_state_t *afl, u8 *queue_fn);
vis_config_t *visualizer_get_config(afl_state_t *afl);

#endif /* ifndef _AFL_VISUALIZE_H */
