<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Nakipelo\Orchid2FA\Support\Orchid;

uses(RefreshDatabase::class);

/**
 * Spec §4.5, §10: `orchid-2fa:rotate-remember-tokens`.
 */
it('clears the remember tokens of all users in one query, so old remember cookies stop working', function () {
    $first = tfUser('first@example.com');
    $second = tfEnforcedUser('second@example.com');
    $first->forceFill(['remember_token' => 'token-1'])->save();
    $second->forceFill(['remember_token' => 'token-2'])->save();
    $updatedAt = $first->refresh()->updated_at;
    $recaller = Orchid::guard()->getRecallerName();
    $cookie = $first->id.'|token-1|'.$first->password;

    $this->withCookie($recaller, $cookie)->get(route('platform.profile'))->assertOk();
    $this->newBrowser();

    DB::enableQueryLog();
    $this->travel(5)->minutes();

    $this->artisan('orchid-2fa:rotate-remember-tokens')
        ->expectsConfirmation('All "remember me" cookies of the admin panel users will stop working. Continue?', 'yes')
        ->expectsOutputToContain('Remember tokens cleared for 2 user(s).')
        ->assertSuccessful();

    $updates = collect(DB::getQueryLog())->filter(fn ($query) => str_starts_with(strtolower($query['query']), 'update'));
    expect($updates)->toHaveCount(1)
        ->and($first->refresh()->remember_token)->toBeNull()
        ->and($second->refresh()->remember_token)->toBeNull()
        ->and($first->updated_at->equalTo($updatedAt))->toBeTrue();

    $this->withCookie($recaller, $cookie)->get(route('platform.main'))->assertRedirect(route('platform.login'));
    $this->assertGuest();
});

it('rotates without asking with --force', function () {
    $user = tfUser();
    $user->forceFill(['remember_token' => 'token'])->save();

    $this->artisan('orchid-2fa:rotate-remember-tokens', ['--force' => true])->assertSuccessful();

    expect($user->refresh()->remember_token)->toBeNull();
});

it('changes nothing when the confirmation is declined', function () {
    $user = tfUser();
    $user->forceFill(['remember_token' => 'token'])->save();

    $this->artisan('orchid-2fa:rotate-remember-tokens')
        ->expectsConfirmation('All "remember me" cookies of the admin panel users will stop working. Continue?', 'no')
        ->assertFailed();

    expect($user->refresh()->remember_token)->toBe('token');
});

it('does not end active sessions', function () {
    $user = tfUser();
    $user->forceFill(['remember_token' => 'token'])->save();
    $this->actingAs($user)->get(route('platform.profile'))->assertOk();

    $this->artisan('orchid-2fa:rotate-remember-tokens', ['--force' => true])->assertSuccessful();

    $this->get(route('platform.profile'))->assertOk();
    $this->assertAuthenticatedAs($user);
});
