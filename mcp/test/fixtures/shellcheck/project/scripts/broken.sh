#!/bin/sh
# Does not parse: the if is never closed.
if [ "$1" = x ]; then
  echo ok
