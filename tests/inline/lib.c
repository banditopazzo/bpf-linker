#include "lib.h"

static void *(*const bpf_map_lookup_elem)(void *map,
                                          const void *key) = (void *)1;

#define SEC(name)                                                              \
  _Pragma("GCC diagnostic push")                                               \
      _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")               \
          __attribute__((section(name), used)) _Pragma("GCC diagnostic pop")

#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define PINNING_ENABLED 1

struct bpf_map_def_aya {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  // aya extensions:
  unsigned int id;      // unused
  unsigned int pinning; // enables pinning
};

struct bpf_map_def_aya SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct test_s),
    .max_entries = 1,
    .pinning = PINNING_ENABLED,
};

__attribute__((always_inline)) __attribute__((used)) struct test_s *func0() {
  unsigned int key = 0;
  struct test_s *p = bpf_map_lookup_elem(&events, &key);
  return p;
}
