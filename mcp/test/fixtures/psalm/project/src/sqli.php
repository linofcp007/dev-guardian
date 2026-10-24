<?php
$pdo = new PDO('sqlite::memory:');
$pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
