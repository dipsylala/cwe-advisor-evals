<?php

class CartRepository
{
    public function loadCart(PDO $pdo, int $userId): array
    {
        $stmt = $pdo->prepare("SELECT cart_data FROM carts WHERE user_id = ?");
        $stmt->execute([$userId]);
        $row = $stmt->fetch();

        if ($row === false) {
            return [];
        }

        // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
        return unserialize($row['cart_data']);
    }
}
