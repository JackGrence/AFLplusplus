#ifndef _AFL_VISUALIZER_H
#define _AFL_VISUALIZER_H

#include "config.h"
#include "types.h"
#include "afl-fuzz.h"
#include "visrequester.h"
#include "list.h"

typedef struct vis_constraint {

  u32 offset;
  u32 length;
  u8  *data;

} vis_constraint_t;

void visualizer_constraints_get(afl_state_t *afl);
void visualizer_constraints_set(afl_state_t *afl, u8 *buf, u32 size);
void visualizer_afl(afl_state_t *afl);
void visualizer_prepare_seed(afl_state_t *afl, u8 *queue_fn);

#endif /* ifndef _AFL_VISUALIZE_H */
