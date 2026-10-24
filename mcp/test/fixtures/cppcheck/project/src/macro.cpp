// An unknown macro cppcheck cannot parse past: the analysis of this file ends here.
int first() { int *p = 0; return *p; }
void loop(int n) {
    for (int i = 0; i < n; i++) UNKNOWN_LOOP_MACRO { }
}
