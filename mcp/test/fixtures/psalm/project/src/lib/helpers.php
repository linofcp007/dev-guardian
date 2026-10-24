<?php
function get_param(string $k): string {
    return (string) $_GET[$k];
}
function run_it(string $cmd): void {
    shell_exec($cmd);
}
