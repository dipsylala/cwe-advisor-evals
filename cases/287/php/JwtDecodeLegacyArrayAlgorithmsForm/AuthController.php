<?php

// composer.json (excerpt): "firebase/php-jwt": "^5.5"
// Pinned to the 5.x line: the array-of-algorithms call form used below was
// removed with a TypeError starting in firebase/php-jwt 6.0.0, so this file
// only compiles/runs as written against 5.5.x.

namespace App\Http\Controllers;

use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

class AuthController
{
    /** PEM-encoded RSA public key used to verify RS256-signed tokens. */
    private string $rsaPublicKey;

    /** Shared HMAC secret used to verify HS256-signed tokens. */
    private string $hmacSecret;

    public function __construct(string $rsaPublicKey, string $hmacSecret)
    {
        $this->rsaPublicKey = $rsaPublicKey;
        $this->hmacSecret = $hmacSecret;
    }

    /**
     * Authenticates an API request from its bearer token and returns the
     * decoded claims, or null if the token is missing or invalid.
     */
    public function authenticateRequest(array $headers): ?object
    {
        $authHeader = $headers['Authorization'] ?? '';
        if (!preg_match('/^Bearer\s+(\S+)$/', $authHeader, $matches)) {
            return null;
        }

        $jwt = $matches[1];
        $publicKey = $this->rsaPublicKey;

        try {
            // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
            $decoded = JWT::decode($jwt, $publicKey, ['RS256', 'HS256']);
        } catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
            return null;
        }

        return $decoded;
    }
}
