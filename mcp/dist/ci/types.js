/**
 * Shapes shared by the CI entry point.
 *
 * `CiExitCode` is a union rather than bare numbers because the exit code IS
 * the contract with the pipeline: 2 in particular exists so that "a scanner
 * did not run" can never be mistaken for "nothing was found".
 */
export const CI_EXIT = {
    PASS: 0,
    GATE_FAILED: 1,
    INCOMPLETE_SCAN: 2,
    USAGE_ERROR: 3,
};
//# sourceMappingURL=types.js.map