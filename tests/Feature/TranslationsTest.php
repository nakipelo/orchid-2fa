<?php

declare(strict_types=1);

/**
 * @param  array<array-key, mixed>  $lines
 * @return array<string, string>
 */
function orchid2faFlattenLines(array $lines, string $prefix = ''): array
{
    $flat = [];

    foreach ($lines as $key => $value) {
        if (is_array($value)) {
            $flat += orchid2faFlattenLines($value, $prefix.$key.'.');
        } else {
            $flat[$prefix.$key] = (string) $value;
        }
    }

    return $flat;
}

/**
 * @return array<string, string>
 */
function orchid2faLines(string $locale): array
{
    return orchid2faFlattenLines(require dirname(__DIR__, 2).'/lang/'.$locale.'/messages.php');
}

it('ships the same keys in every locale', function (string $locale) {
    $en = array_keys(orchid2faLines('en'));
    $other = array_keys(orchid2faLines($locale));

    sort($en);
    sort($other);

    expect($other)->toBe($en);
})->with(['ru']);

it('keeps the same placeholders in every locale', function (string $locale) {
    $placeholders = static function (string $line): array {
        preg_match_all('/:([a-z_]+)/', $line, $matches);
        $names = array_unique($matches[1]);
        sort($names);

        return $names;
    };

    $other = orchid2faLines($locale);

    foreach (orchid2faLines('en') as $key => $line) {
        expect($placeholders($other[$key]))->toBe($placeholders($line), "Placeholders of [{$key}] differ in [{$locale}].");
    }
})->with(['ru']);

it('has no empty lines', function (string $locale) {
    foreach (orchid2faLines($locale) as $key => $line) {
        expect(trim($line))->not->toBe('', "[{$key}] is empty in [{$locale}].");
    }
})->with(['en', 'ru']);

it('defines every literal key the package uses', function () {
    $root = dirname(__DIR__, 2);
    $files = [$root.'/resources/views/challenge.blade.php'];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root.'/src')) as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $files[] = $file->getPathname();
        }
    }

    $used = [];

    foreach ($files as $file) {
        preg_match_all("/orchid-2fa::messages\.([a-z_.]*[a-z_])'/", (string) file_get_contents($file), $matches);
        array_push($used, ...$matches[1]);
    }

    expect($used)->not->toBeEmpty();

    foreach (array_unique($used) as $key) {
        expect(__('orchid-2fa::messages.'.$key))->not->toBe('orchid-2fa::messages.'.$key, "[{$key}] is missing.");
    }
});
