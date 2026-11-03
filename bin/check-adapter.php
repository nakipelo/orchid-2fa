<?php

declare(strict_types=1);

/*
 * Spec §5.1 / §11 stage 1: Orchid names (`platform.` config keys and route names,
 * the `platform::` view namespace, `Orchid\` classes) may appear in src/ only
 * inside the adapter src/Support/Orchid.php.
 *
 * Usage: php bin/check-adapter.php [src-dir]
 */

$root = realpath($argv[1] ?? __DIR__.'/../src');

if ($root === false || ! is_dir($root)) {
    fwrite(STDERR, "Source directory not found.\n");
    exit(2);
}

$adapter = $root.DIRECTORY_SEPARATOR.'Support'.DIRECTORY_SEPARATOR.'Orchid.php';
$pattern = '/platform\.|platform::|Orchid\\\\/';
$violations = [];

$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));

foreach ($files as $file) {
    /** @var SplFileInfo $file */
    if (! $file->isFile() || $file->getPathname() === $adapter) {
        continue;
    }

    foreach (file($file->getPathname()) ?: [] as $number => $line) {
        // The package's own namespace contains "Orchid2FA\", which is not Orchid.
        $line = str_replace('Orchid2FA\\', '', $line);

        if (preg_match($pattern, $line) === 1) {
            $violations[] = sprintf('%s:%d: %s', substr($file->getPathname(), strlen($root) + 1), $number + 1, trim($line));
        }
    }
}

if ($violations !== []) {
    fwrite(STDERR, "Orchid names found outside src/Support/Orchid.php:\n  ".implode("\n  ", $violations)."\n");
    exit(1);
}

fwrite(STDOUT, "OK: platform./platform::/Orchid\\ only in src/Support/Orchid.php\n");
