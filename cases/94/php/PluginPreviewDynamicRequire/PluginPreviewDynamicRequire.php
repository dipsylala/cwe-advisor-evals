<?php

final class PluginPreviewDynamicRequire
{
    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
