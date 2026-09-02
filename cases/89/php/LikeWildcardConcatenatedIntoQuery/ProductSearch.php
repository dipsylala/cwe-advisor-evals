<?php

function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'");

    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    $stmt->execute();
    return $stmt->fetchAll();
}
