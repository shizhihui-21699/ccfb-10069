#include <cstdio>

#include "test_harness.h"

int main(int argc, char** argv) {
  const char* filter = argc > 1 ? argv[1] : "";
  return sctest::RunAll(filter);
}
