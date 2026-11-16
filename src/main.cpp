#include <cstdio>
#include <string>
#include <vector>

#include "cli.h"

int main(int argc, char** argv) {
  std::vector<std::string> args;
  args.reserve(static_cast<size_t>(argc > 0 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
  try {
    return scgen::RunCli(args);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "fatal: %s\n", error.what());
    return 2;
  }
}
