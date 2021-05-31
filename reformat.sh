#!/bin/bash
root=$(git rev-parse --show-toplevel)
if [[ $? -ne 0 ]]; then
   echo "git root not found"
   exit 1
fi
find $root -type f -regex '.*\.[ch]p?p?$' -exec clang-format -i '{}' \;

