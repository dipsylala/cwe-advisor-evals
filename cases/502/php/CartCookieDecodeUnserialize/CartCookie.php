<?php

final class CartCookie
{
    public static function decode(string $encoded): mixed
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false) {
            return ['items' => []];
        }

        return unserialize($payload);
    }
}
