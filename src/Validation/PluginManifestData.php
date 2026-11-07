<?php

namespace Openframe\PluginMarketSdk\Validation;

readonly class PluginManifestData
{
    /**
     * @param  list<string>  $providers
     * @param  list<array{title: string, route: string, icon?: ?string, group?: ?string, order?: int}>  $menus
     * @param  list<string>  $requiredModules
     */
    public function __construct(
        public string $name,
        public string $alias,
        public string $version,
        public ?string $description,
        public ?string $author,
        public array $providers,
        public array $menus,
        public ?string $requiredPhp,
        public array $requiredModules,
    ) {}

    /**
     * Build the DTO from a parsed module.json payload.
     *
     * @param  array<string, mixed>  $json
     */
    public static function fromArray(array $json): self
    {
        return new self(
            name: (string) $json['name'],
            alias: (string) $json['alias'],
            version: (string) $json['version'],
            description: isset($json['description']) ? (string) $json['description'] : null,
            author: isset($json['author']) ? (string) $json['author'] : null,
            providers: array_values(array_filter(
                is_array($json['providers'] ?? null) ? $json['providers'] : [],
                fn (mixed $provider): bool => is_string($provider) && $provider !== '',
            )),
            menus: array_values(array_filter(
                is_array($json['menus'] ?? null) ? $json['menus'] : [],
                fn (mixed $menu): bool => is_array($menu) && isset($menu['title'], $menu['route']),
            )),
            requiredPhp: isset($json['required_php']) ? (string) $json['required_php'] : null,
            requiredModules: array_values(array_filter(
                is_array($json['required_modules'] ?? null) ? $json['required_modules'] : [],
                fn (mixed $module): bool => is_string($module) && $module !== '',
            )),
        );
    }
}
