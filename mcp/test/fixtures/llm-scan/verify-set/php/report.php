<?php

declare(strict_types=1);

function step0(array $report, array $lines, $db, string $dir, string $content): void
{
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 3 for " . $report['id']);
    error_log("report step 4 for " . $report['id']);
    $total5 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name6 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total7 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name8 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
}

function step1(array $report, array $lines, $db, string $dir, string $content): void
{
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name1 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total2 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name3 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 4 for " . $report['id']);
    error_log("report step 5 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name7 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows8 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 9 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $total11 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name13 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows14 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name15 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 16 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name18 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total19 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total20 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name21 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows22 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows24 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name25 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 26 for " . $report['id']);
    $total27 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total28 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name29 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows30 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows31 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total32 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total33 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name34 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
}

function step2(array $report, array $lines, $db, string $dir, string $content): void
{
    $name0 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows1 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name2 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total3 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total4 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 6 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 8 for " . $report['id']);
    $total9 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 10 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $rows12 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 13 for " . $report['id']);
    $total14 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $rows15 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $total17 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows20 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows21 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows22 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name23 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 24 for " . $report['id']);
    error_log("report step 25 for " . $report['id']);
    error_log("report step 26 for " . $report['id']);
    $name27 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows28 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows30 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name31 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 32 for " . $report['id']);
    $rows33 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 36 for " . $report['id']);
    $rows37 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 39 for " . $report['id']);
    error_log("report step 40 for " . $report['id']);
    $total41 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total42 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 43 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $rows48 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 50 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $total52 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name53 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total54 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $total59 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total60 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 61 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $total63 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 66 for " . $report['id']);
    $rows67 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 68 for " . $report['id']);
    $rows69 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name70 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows71 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total72 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name74 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 75 for " . $report['id']);
    $name76 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total77 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 78 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name80 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name83 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name84 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 85 for " . $report['id']);
    $name86 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 87 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 89 for " . $report['id']);
}

function step3(array $report, array $lines, $db, string $dir, string $content): void
{
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name1 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total2 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name3 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows5 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name7 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name8 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name9 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total10 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 13 for " . $report['id']);
}

function step4(array $report, array $lines, $db, string $dir, string $content): void
{
    $total0 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $rows1 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total2 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 3 for " . $report['id']);
    error_log("report step 4 for " . $report['id']);
    $name5 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 6 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name8 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name9 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total10 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows12 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $total14 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total15 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 16 for " . $report['id']);
    $rows17 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name18 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 19 for " . $report['id']);
    $name20 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 21 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name26 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total27 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name28 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name29 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name30 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total31 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $rows32 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 33 for " . $report['id']);
    $rows34 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total35 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $rows38 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 39 for " . $report['id']);
    error_log("report step 40 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $total42 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total43 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $rows44 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 45 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows47 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name49 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows51 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 52 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 54 for " . $report['id']);
    $rows55 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name59 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 63 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name65 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 66 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows68 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total69 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $total72 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 73 for " . $report['id']);
    $name74 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows75 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 76 for " . $report['id']);
    $name77 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 78 for " . $report['id']);
    error_log("report step 79 for " . $report['id']);
    $name80 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name81 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows82 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows84 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 85 for " . $report['id']);
    $name86 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total87 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name88 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 90 for " . $report['id']);
    $rows91 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name92 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 94 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 98 for " . $report['id']);
    error_log("report step 99 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 101 for " . $report['id']);
    $total102 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total103 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $name104 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 105 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 107 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name109 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows110 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 112 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $rows115 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 116 for " . $report['id']);
    $rows117 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows118 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 119 for " . $report['id']);
    $total120 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 122 for " . $report['id']);
    $rows123 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total124 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 125 for " . $report['id']);
    error_log("report step 126 for " . $report['id']);
    $rows127 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total128 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name130 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows131 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name133 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $total135 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $rows136 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name137 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows138 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total139 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 140 for " . $report['id']);
    $rows141 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total142 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows144 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $name146 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total147 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows149 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total150 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $rows151 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows152 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows153 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows154 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name155 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $total157 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows160 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 161 for " . $report['id']);
    error_log("report step 162 for " . $report['id']);
    error_log("report step 163 for " . $report['id']);
    $total164 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total165 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $rows166 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 167 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 170 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $total172 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 175 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    error_log("report step 178 for " . $report['id']);
    $name179 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 181 for " . $report['id']);
    $rows182 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total183 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $total185 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    error_log("report step 186 for " . $report['id']);
    error_log("report step 187 for " . $report['id']);
    $rows188 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows189 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 190 for " . $report['id']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $total194 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    $rows197 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $total198 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $rows201 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $name202 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $rows203 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    $rows204 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name206 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name207 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    error_log("report step 208 for " . $report['id']);
    $name209 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $name210 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name213 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $name217 = htmlspecialchars($report['name'], ENT_QUOTES, 'UTF-8');
    $total218 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $total219 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    file_put_contents($dir . '/' . $_POST['file'], $content);
    $total222 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    $rows223 = $db->query("SELECT * FROM reports WHERE owner = " . $_GET['owner']);
    error_log("report step 224 for " . $report['id']);
    error_log("report step 225 for " . $report['id']);
    $total226 = array_sum(array_map(fn($l) => $l['price'] * $l['qty'], $lines));
    file_put_contents($dir . '/' . $_POST['file'], $content);
    error_log("report step 228 for " . $report['id']);
    if (!isset($_SESSION['user'])) { header('Location: /login'); exit; }
}

