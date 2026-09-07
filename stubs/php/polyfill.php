<?php
// Loaded by PHPStan (phpstan.neon bootstrapFiles) before analysis. Some PHP builds ship mbstring
// without its regex functions (no oniguruma); Larastan's Eloquent analysis calls mb_split through
// Illuminate\Support\Str. Analysis-time stand-in only; nothing here reaches a fixture or a fix.
if (!function_exists('mb_split')) {
    function mb_split(string $pattern, string $string, int $limit = -1): array|false
    {
        return preg_split('/' . str_replace('/', '\/', $pattern) . '/u', $string, $limit);
    }
}
