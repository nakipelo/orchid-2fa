<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Config\Repository;

/**
 * Codes in the cache (`cache.store`), keyed `orchid-2fa:code:{user_id}` (spec §5.9).
 *
 * One active code per user: storing a new one replaces (annuls) the previous one.
 */
class CodeStore
{
    public function __construct(
        protected CacheFactory $cache,
        protected Repository $config,
    ) {}

    public function get(int|string $userId): ?StoredCode
    {
        $code = StoredCode::fromArray($this->store()->get($this->key($userId)));

        return $code !== null && ! $code->isExpired() ? $code : null;
    }

    public function put(int|string $userId, StoredCode $code): void
    {
        $this->store()->put($this->key($userId), $code->toArray(), max(1, $code->expiresAt - now()->getTimestamp()));
    }

    public function forget(int|string $userId): void
    {
        $this->store()->forget($this->key($userId));
    }

    /**
     * Mark the code of a challenge as used, atomically: only the first caller gets true.
     * `Cache::add` is atomic in the cache stores Laravel ships, unlike get + forget.
     */
    public function claim(int|string $userId, StoredCode $code): bool
    {
        return $this->store()->add(
            'orchid-2fa:used:'.$userId.':'.$code->challengeId,
            true,
            max(1, $code->expiresAt - now()->getTimestamp()),
        );
    }

    public function hashCode(#[\SensitiveParameter] string $code, string $challengeId): string
    {
        return hash_hmac('sha256', $code.'|'.$challengeId, $this->secret());
    }

    public function hashDestination(string $destination): string
    {
        return hash_hmac('sha256', $destination, $this->secret());
    }

    public function key(int|string $userId): string
    {
        return 'orchid-2fa:code:'.$userId;
    }

    protected function store(): Cache
    {
        $store = $this->config->get('orchid-2fa.cache.store');

        return $this->cache->store(is_string($store) && $store !== '' ? $store : null);
    }

    protected function secret(): string
    {
        return (string) $this->config->get('app.key');
    }
}
