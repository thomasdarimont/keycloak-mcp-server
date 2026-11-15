#!/usr/bin/env bash
# What a change needs from the CI: reads the changed files, one per line, and prints
#
#   code=true|false    something the build, the tests, the image or the distribution depend on changed
#   docs=true|false    docs/*.md changed: they are packaged and a unit test reads the settings they name
#
# README files outside the build (the repository's, the examples', the conformance suite's) need neither; the spelling
# check runs on everything anyway. Everything not listed here counts as code, Markdown included: the prompts and the
# README files under modules/ are packaged.
set -euo pipefail
code=false
docs=false
while IFS= read -r file; do
  case "$file" in
    "") ;;
    docs/*.md) docs=true ;;
    README.md | examples/README.md | examples/*/README.md | conformance/README.md) ;;
    *) code=true ;;
  esac
done
echo "code=$code"
echo "docs=$docs"
