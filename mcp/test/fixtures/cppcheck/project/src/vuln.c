/* Deliberately buggy: the cppcheck e2e fixture (test/e2e/cppcheckSast.test.ts). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int null_deref(void) {
    int *p = NULL;
    return *p;
}

void out_of_bounds(void) {
    int arr[10];
    arr[10] = 1;
}

void leak(void) {
    char *buf = malloc(16);
    buf[0] = 'x';
}

void overrun(void) {
    char small[4];
    strcpy(small, "far too long for four bytes");
}

void obsolete(char *line) {
    gets(line);
}

int uninit(void) {
    int x;
    return x;
}
