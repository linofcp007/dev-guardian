<?php
// POSITIVE CONTROL FOR p/php: twelve classic PHP vulnerabilities, so that a
// zero on the bug fixtures means "found nothing" rather than "the pack is
// inert here". Measured: p/php fires NINE times on this file, so it is live
// and PHP-aware.
//
// p/security-audit fires ZERO times on it. That is not a bug in this file --
// it is a measured property of that pack, now seen in two languages (C# and
// PHP), and it is why the only claim the test makes about p/security-audit is
// `paths.scanned > 0`.
//
// Nothing in here is meant to run. It is scanner input.
function a(): void { eval($_GET['code']); }
function b(): void { system($_GET['cmd']); }
function c(): void { echo shell_exec($_POST['x']); }
function d(\PDO $db): void { $db->query("SELECT * FROM u WHERE id = " . $_GET['id']); }
function e(mysqli $conn): void { mysqli_query($conn, "SELECT * FROM u WHERE n = '" . $_GET['n'] . "'"); }
function f(): void { echo $_GET['name']; }
function g(): void { include $_GET['page']; }
function h(): void { $x = unserialize($_COOKIE['data']); var_dump($x); }
function i(): string { return md5($_POST['pw']); }
function j(): void { header('Location: ' . $_GET['url']); }
function k(): void { $name = $_GET['f']; readfile("/var/data/$name"); }
function l(): void { setcookie('s', 'v', 0, '/', '', false, false); }
