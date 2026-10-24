#!/bin/bash
# Deliberately bad: the shellcheck e2e fixture (test/e2e/shellcheckQuality.test.ts).
rm -rf $DIR/*
cd /tmp
for f in $(ls *.txt); do echo $f; done
