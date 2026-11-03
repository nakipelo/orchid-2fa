# nakipelo/orchid-2fa — спецификация v0.1

Статус: черновик для согласования. Сверено с `orchid/platform` 14.53.0 (тег) и `master`.

## 1. Цель и границы

Второй фактор (одноразовый код на e-mail) для входа в админку Orchid по паролю.

**В v0.1:**

- вход по паролю с кодом на почту, схема «сначала код, потом логин»;
- обязательность для пользователей с правом `platform.2fa.required` или для всех (флаг конфига), добровольное включение в профиле;
- доверенное устройство;
- экран профиля 2FA со ссылкой из `UserProfileScreen` (Layout), сброс администратором (Layout для `UserEditScreen` и artisan-команда);
- ротация remember-cookie (при включении 2FA и командой `orchid-2fa:rotate-remember-tokens`);
- уведомление о смене e-mail; события, переводы en/ru.

**Вне v0.1:** TOTP, резервные коды, SMS/Telegram, поддержка следующего мажора Orchid (`platform` → `orchid`), самостоятельное восстановление доступа пользователем, интеграция со своим логином приложения при `platform.auth = false`. Пакет не закрывает вход в тот же guard мимо Orchid (Breeze/Fortify/свои маршруты/API-токены): в v0.1 это ответственность приложения, в README — предупреждение (§9). Кандидат на v0.2 — middleware в группе `platform` «залогинен, но 2FA в этой сессии не пройдена» (пропускает `viaRemember` и impersonation).

## 2. Пакет и окружение

| Параметр | Значение |
|---|---|
| Composer | `nakipelo/orchid-2fa`, публичный, MIT |
| Неймспейс | `Nakipelo\Orchid2FA` |
| Провайдер | `Nakipelo\Orchid2FA\Orchid2FAServiceProvider` (auto-discovery) |
| Конфиг | `config/orchid-2fa.php` (публикуется, тег `orchid-2fa-config`) |
| PHP | `^8.2`; Laravel 13 требует PHP 8.3+, поэтому 8.2 — только для L11–12 (указано в README, ограничивает матрицу CI) |
| Laravel | `^11.35 \|\| ^12.0 \|\| ^13.0`: минимум 11.35, потому что Orchid 14.53 объявляет `conflict` `laravel/framework <=11.34.0` |
| Orchid | `orchid/platform ^14.53` |
| Guard | `config('platform.guard')`, обязан быть `Illuminate\Auth\SessionGuard`; иначе провайдер бросает исключение при загрузке |

Первый потребитель — внутренний проект, но API публичное: имена классов, конфиг, события, маршруты и view после 0.1.0 меняются только по semver. Матрица CI минимальная: (PHP 8.2, L11), (PHP 8.3, L12), (PHP 8.4, L13), обе с `--prefer-lowest` и `--prefer-stable` для крайних точек.

## 3. Термины

- **Первичная аутентификация** — проверка email и пароля через `SessionGuard::validate()`, без входа.
- **Pending** — запись в сессии о том, что пароль верен и ждём код: `user_id`, `remember`, `created_at`, `challenge_id`. Живёт `pending_ttl` (10 мин).
- **Вызов (challenge)** — выпуск и отправка кода по каналу. Код хранится в cache только хешем, вместе со счётчиком попыток.
- **Канал** — способ доставки и проверки второго фактора (`TwoFactorChannel`). В v0.1 есть только `email`.
- **Принудительный пользователь** — включён `enforce_all` или у пользователя есть право `platform.2fa.required`.
- **Добровольный пользователь** — включил 2FA сам: `enabled_at` не null.
- **Требуется 2FA** — пользователь принудительный или добровольный.
- **Доверенное устройство** — браузер с действующей cookie доверия для этого пользователя.
- **Адаптер** — `Nakipelo\Orchid2FA\Support\Orchid`: единственное место, где встречаются имена Orchid.

## 4. Сценарии

### 4.1. Вход без 2FA
1. `POST platform.login.auth`: работает контроллер пакета, валидация как у Orchid (`email`, `password` — `required|string`).
2. Контроллер диспатчит `Illuminate\Auth\Events\Attempting`, затем `guard->validate(email, password)`. `validate()`, в отличие от `attempt()`, не шлёт `Attempting`/`Failed` и не рехеширует пароль, поэтому всё это делает контроллер пакета. При неверном пароле — `Failed` и та же `ValidationException` на `email` с тем же текстом, что у Orchid. При верном — сразу `provider->rehashPasswordIfRequired($user, $credentials)`: после шага кода пароля в запросе уже нет, а хранить его в pending нельзя.
3. 2FA не требуется → шаг «финальный вход» (§4.3).

### 4.2. Вход с 2FA
1. Пункты 1–2 из §4.1.
2. 2FA требуется, доверенного устройства нет (§4.4) → `session()->regenerate()`, в сессию кладётся pending (ключ `orchid-2fa.pending`).
3. Если для пользователя уже есть активный код (не истёк, попытки остались, привязан к текущему адресу), новый не отправляется. Иначе выпускается и отправляется новый код (§4.9, §4.10), старый аннулируется.
4. Редирект на `platform.two-factor.challenge`. Для `wantsJson()` — `200 {"two_factor": true, "redirect": "<url>"}`.
5. Экран кода. При `POST platform.two-factor.verify`:
   - pending нет или истёк → редирект на `platform.login` с сообщением «сессия входа истекла»;
   - код неверный → `TwoFactorFailed(reason: invalid_code)`, попытка засчитана; на 5-й неверной код аннулируется, `TwoFactorLockedOut`, сообщение «код больше недействителен, запросите новый»;
   - код верный → код удаляется из cache, pending удаляется, при первом успехе выставляется `confirmed_at`, при отмеченной галочке выдаётся cookie доверия (§4.4), `TwoFactorPassed`, финальный вход (§4.3).
6. «Войти под другим пользователем» (`POST platform.two-factor.cancel`) удаляет pending, забывает lock-cookie и редиректит на `platform.login`.

### 4.3. Финальный вход (общий для §4.1 и §4.2)
`guard->login($user, $remember)` → `session()->regenerate()` → если `$remember`, ставится lock-cookie как у Orchid: `CookieJar::forever(guard->getName().'__orchid_lock', $user->id)` → `redirect()->intended(route(config('platform.index')))`, для JSON — `204`. Имя lock-cookie — именно `guard->getName().'__orchid_lock'`, где `SessionGuard::getName()` = `login_{guard}_{sha1(SessionGuard::class)}`, а не `{guard}__orchid_lock`: адаптер повторяет `LoginController::nameForLock()` Orchid буквально. Все имена берутся из адаптера.

### 4.4. Доверенное устройство
- Галочка «Доверять этому устройству N дней» на экране кода видна, только если `trusted_devices.enabled`.
- После верного кода выдаётся cookie (§7.6) с `user_id`, `version = trusted_devices_version`, `expires`.
- На шаге 2 §4.2 действующая cookie (подпись верна, `user_id` совпадает, `version` равна текущей, срок не вышел) отменяет вызов: сразу финальный вход и `TwoFactorPassed(via: trusted_device)`. Пароль проверяется всегда.
- Инвалидация — инкремент `trusted_devices_version`: кнопка «Выйти со всех доверенных устройств», смена пароля, выключение 2FA, сброс администратором.

### 4.5. Remember
Вход по remember-cookie Laravel (`viaRemember`) код не спрашивает. Remember-cookie выдаётся только в финальном входе, то есть после пройденного 2FA, если оно требуется. Чтобы это было верно и для cookie, выданных раньше:
- при включении 2FA пользователю — добровольном (§4.7) и при создании записи принудительного пользователя на первом вызове (§4.2) — пакет ротирует его `remember_token` (`provider->updateRememberToken($user, Str::random(60))`); старые remember-cookie перестают работать;
- для cookie, выданных до установки пакета, — `php artisan orchid-2fa:rotate-remember-tokens`: обнуляет `remember_token` у всех пользователей модели провайдера guard одним запросом, с подтверждением, `--force` его пропускает. Активные сессии не завершаются. В README — шаг «после установки выполните».

### 4.6. Impersonation
`Orchid\Access\Impersonation::loginAs()` / `logout()` работают через `loginUsingId` и маршрут логина не затрагивают, поэтому 2FA не спрашивается. Пакет в них не вмешивается. Тест фиксирует это поведение.

### 4.7. Включение и выключение в профиле (`platform.profile.two-factor`)
- **Вход на экран**: Layout `TwoFactorProfileLinkLayout` на `UserProfileScreen` (кнопка-ссылка со статусом, подключается одной строкой в `layout()` стаба, §6). Пункт в основном меню — только при `menu.enabled` (по умолчанию выключен): меню профиля в Orchid 14 нет, `registerProfileMenu()` помечен `@deprecated` и сливается в общее меню.
- **Включить** (для добровольного пользователя): «Отправить код» → код на текущий e-mail (те же лимиты) → ввод → `enabled_at = confirmed_at = now()`, `channel = email`, ротация `remember_token` (§4.5). Без верного кода 2FA не включается.
- **Выключить**: доступно только добровольному и подтверждается кодом на текущий e-mail (тот же поток и лимиты, что при включении). Выставляет `enabled_at = null`, `confirmed_at = null` и инкрементирует `trusted_devices_version`. Принудительный пользователь видит статус «обязательно для вашей учётной записи» без кнопки выключения; сервер повторно проверяет `TwoFactorPolicy::isEnforced()` и отклоняет запрос на выключение (отправку кода и подтверждение) от принудительного пользователя.
- **Выйти со всех доверенных устройств**: инкремент `trusted_devices_version`, кнопка доступна при любом статусе.
- Принудительному пользователю запись в таблице создаётся лениво, при первом вызове (с ротацией `remember_token`, §4.5). `confirmed_at` выставляется при первом успешном коде.

### 4.8. Сброс администратором
- `UserEditScreen`: Layout пакета с кнопкой «Сбросить 2FA». Видна при праве `platform.systems.users.2fa-reset`.
- `php artisan orchid-2fa:reset {email}`: та же операция, с подтверждением; `--force` подтверждение пропускает.
- Операция сброса: `enabled_at = null`, `confirmed_at = null`, инкремент `trusted_devices_version`, удаление активного кода и счётчиков. Для принудительного пользователя это значит, что следующий вход снова выдаст вызов на текущий e-mail. Это и есть аварийный доступ v0.1: администратор исправляет адрес в карточке пользователя и сбрасывает 2FA. Других обходов нет.

### 4.9. Смена e-mail при включённом 2FA
- Изменение `email` у модели (профиль, `UserEditScreen`, любой `save()`) ловит трейт `HasTwoFactor`.
- На старый адрес уходит `TwoFactorEmailChangedNotification`. 2FA не выключается. `confirmed_at = null`, активный код аннулируется.
- Следующий вход шлёт код на новый адрес. Успех подтверждает адрес (`confirmed_at = now()`).
- Массовые `update()` через query builder событий модели не вызывают, и уведомление в этом случае не уходит (ограничение описано в README).
- `UserProfileScreen::save` Orchid меняет e-mail без пароля. Пакет стаб не меняет: README рекомендует добавить в стаб подтверждение текущим паролем. Остаточный риск принят (§9).

### 4.10. Ошибка отправки (fail-closed)
Исключение транспорта при синхронной отправке → лог `error`, `TwoFactorFailed(reason: delivery_failed)`, сообщение пользователю «не удалось отправить код, попробуйте позже». Вход не выполняется. Pending сохраняется, а значит, «Отправить повторно» работает в пределах лимитов. Неудачная отправка тоже засчитывается в лимиты. В режиме очереди (`notification.queue = true`) ошибка асинхронна: пользователь видит экран кода, а код не приходит. Это ограничение режима очереди описано в README.

### 4.11. Лимиты
- Повторная отправка (`POST platform.two-factor.resend`): не чаще раза в `resend.cooldown` (60 с) и не больше `resend.max_per_hour` (5) отправок в час на пользователя. В часовой лимит входят все отправки: при входе, повторные и из профиля.
- Превышение → `TwoFactorLockedOut(reason: send_limit)`, сообщение «попробуйте позже (через N мин)». Аккаунт не блокируется, пароль продолжает проверяться.
- Ввод: `code.max_attempts` (5) неверных попыток на код, затем код аннулируется.
- Дополнительно к счётчикам на пользователя маршруты `verify` и `resend` закрыты `throttle` по IP (`routes.throttle`).
- Обратный отсчёт на кнопке «Отправить повторно» берёт время из `RateLimiter::availableIn()`.

## 5. Архитектура и компоненты

```
src/
  Orchid2FAServiceProvider.php
  Support/Orchid.php                      адаптер
  Contracts/TwoFactorChannel.php
  Channels/EmailChannel.php
  Challenge/ChallengeManager.php          выпуск/проверка/лимиты, channel-agnostic
  Challenge/CodeStore.php                 cache: хеш, попытки, привязки
  Challenge/PendingLogin.php              value-object + чтение/запись сессии
  Policy/TwoFactorPolicy.php              requires()/isEnforced()/isEnabled()
  TrustedDevice/TrustedDeviceCookie.php
  Http/Controllers/LoginController.php    POST platform.login.auth
  Http/Controllers/ChallengeController.php show/verify/resend/cancel
  Screens/TwoFactorProfileScreen.php
  Layouts/TwoFactorProfileLinkLayout.php  ссылка на экран 2FA для UserProfileScreen
  Layouts/TwoFactorResetLayout.php
  Concerns/ResetsTwoFactor.php            трейт для UserEditScreen (метод resetTwoFactor)
  Models/TwoFactorAuthentication.php
  Concerns/HasTwoFactor.php               трейт для App\Models\User
  Notifications/TwoFactorCodeNotification.php
  Notifications/TwoFactorEmailChangedNotification.php
  Events/{TwoFactorChallengeSent,TwoFactorPassed,TwoFactorFailed,TwoFactorLockedOut}.php
  Listeners/LogTwoFactorEvents.php
  Console/ResetTwoFactorCommand.php
  Console/RotateRememberTokensCommand.php
database/migrations/xxxx_create_two_factor_authentications_table.php
resources/views/challenge.blade.php        @extends(<адаптер: 'platform::auth'>)
resources/lang/{en,ru}/... 
```

### 5.1. Адаптер `Support\Orchid`
Единственный класс, где встречаются `platform.*`, `platform::` и `Orchid\…`. Остальной код зовёт только его. Минимальный набор методов:

| Метод | v14 |
|---|---|
| `guardName()` / `guard(): SessionGuard` | `config('platform.guard')` + проверка типа |
| `routeNamePrefix()` | `'platform.'` |
| `routeGroup(bool $private, Closure)` | `domain(config('platform.domain'))`, `prefix(Dashboard::prefix('/'))`, `as('platform.')`, `middleware(config('platform.middleware.private' / '.public'))` |
| `loginRoute()`, `loginAuthRoute()`, `loginLockRoute()` | `platform.login`, `platform.login.auth`, `platform.login.lock` |
| `indexUrl()` | `route(config('platform.index'))` |
| `profileRoute()` | `config('platform.profile', 'platform.profile')` |
| `authLayout()`, `viewNamespace()` | `platform::auth`, `platform` |
| `lockCookieName()` | `guard()->getName().'__orchid_lock'` (повтор `LoginController::nameForLock()`) |
| `guestMiddleware()` | `RedirectIfAuthenticated` с `redirectUsing(fn () => indexUrl())`, как в Orchid |
| `registerPermissions(...)`, `registerMenu(...)` | `Dashboard::registerPermissions(ItemPermission)`, `Dashboard::registerMenuElement(Menu)` |
| `loginRoutesEnabled()` | `config('platform.auth', true)` |

### 5.2. Канал
```php
interface TwoFactorChannel
{
    public function name(): string;                                   // 'email'
    public function isAvailableFor(Authenticatable $user): bool;      // есть адрес
    public function destination(Authenticatable $user): string;       // сырой адрес, для привязки кода
    public function maskedDestination(Authenticatable $user): string; // e***@gmail.com
    public function send(Authenticatable $user, string $code, CarbonInterface $expiresAt): void; // бросает DeliveryFailedException
}
```
Генерацию, хранение и проверку кода ведёт `ChallengeManager`, общий для OTP-каналов. Каналы, которые сами проверяют код (TOTP в будущем), реализуют дополнительный `VerifiesOwnCodes::verify(Authenticatable $user, string $code): bool`. В v0.1 его нет. `EmailChannel` берёт адрес из атрибута `channels.email.attribute` (`email`) и шлёт `config('orchid-2fa.notification.class')`. Маска: первая буква локальной части + `***` + `@` + домен целиком.

### 5.3. Маршруты
Все регистрируются через `Orchid::routeGroup()`, имена — с префиксом адаптера.

| Метод | URI (от префикса Orchid) | Имя | Группа | Контроллер |
|---|---|---|---|---|
| POST | `login` | `platform.login.auth` | public, `throttle:60,1`, guest | `LoginController@login` (замещает Orchid) |
| GET | `two-factor` | `platform.two-factor.challenge` | public, guest | `ChallengeController@show` |
| POST | `two-factor` | `platform.two-factor.verify` | public, guest, `routes.throttle` | `ChallengeController@verify` |
| POST | `two-factor/resend` | `platform.two-factor.resend` | public, guest, `routes.throttle` | `ChallengeController@resend` |
| POST | `two-factor/cancel` | `platform.two-factor.cancel` | public, guest | `ChallengeController@cancel` |
| screen | `profile/two-factor` | `platform.profile.two-factor` | private | `TwoFactorProfileScreen` |

Замещение `POST login`: маршрут регистрируется в `$this->app->booted()`, после маршрутов Orchid (Orchid грузит их в booted-колбэке своего `RouteServiceProvider`). В `RouteCollection` маршрут с тем же методом, доменом и URI, добавленный позже, замещает ранний, имя `platform.login.auth` указывает на него. `GET platform.login` не переопределяется. Работоспособность замещения проверяется тестом на этапе 1 (§10, §11): `route('platform.login.auth')` и реальный `POST` на этот URI попадают в контроллер пакета — и без кеша, и после `route:cache`.

**Запасной путь** — если тест этапа 1 не проходит: снимать маршрут Orchid из `RouteCollection` не будем (внутренний API). Вместо этого приложение ставит `platform.auth = false`, а пакет сам регистрирует все маршруты входа Orchid (`routes/auth.php`) под теми же именами и URI, с `POST login` на свой контроллер. Выбор пути фиксируется в этом разделе по итогам этапа 1; при запасном пути меняются шаг установки в README и поведение при `platform.auth = false` (ниже).

**`config('platform.auth') === false`** (основной путь): Orchid свои маршруты входа не регистрирует, пакет тоже не подменяет `POST login` и пишет предупреждение в лог (`warning`, один раз при загрузке). Маршруты экрана кода и профиля регистрируются как обычно.

### 5.4. Middleware
В v0.1 своего middleware нет. При pending пользователь остаётся гостем, и `Orchid\Platform\Http\Middleware\Access` (группа `platform`) сам отправляет его на `platform.login`. Экран кода без pending редиректит на `platform.login`. Вход в тот же guard мимо `platform.login.auth` (Breeze, Fortify, `orchid/fortify`, свой `/login`) 2FA обходит: в v0.1 только предупреждение в README, middleware «залогинен, но 2FA в этой сессии не пройдена» — кандидат на v0.2 (§1).

### 5.5. Модель и миграция
Таблица `two_factor_authentications`:

| Колонка | Тип |
|---|---|
| `id` | bigIncrements |
| `user_id` | unsignedBigInteger, unique, FK `users.id` `cascadeOnDelete` |
| `channel` | string(32), default `email` |
| `enabled_at` | timestamp null: добровольное включение |
| `confirmed_at` | timestamp null: текущий адрес подтверждён кодом |
| `trusted_devices_version` | unsignedInteger, default 1 |
| `created_at`, `updated_at` | timestamps |

Миграция грузится через `loadMigrationsFrom` и публикуется (тег `orchid-2fa-migrations`). Колонок в `users` пакет не добавляет. Тип FK соответствует `users.id` Orchid/Laravel (bigint). Нестандартный ключ решается правкой опубликованной миграции.

Трейт `HasTwoFactor` для `App\Models\User`:
- `twoFactor(): HasOne`;
- `twoFactorRecord(): TwoFactorAuthentication` (firstOrNew);
- `hasTwoFactorEnabled()`;
- `bumpTrustedDevicesVersion()`;
- слушатели модели: `updating` с `isDirty('password')` → инкремент версии; `updated` с `wasChanged('email')` → §4.9.

Без трейта провайдер работает, но доверенные устройства не сбрасываются при смене пароля. При загрузке в `local`/`testing` провайдер пишет предупреждение.

### 5.6. Cookie доверенного устройства
- Имя: `trusted_devices.cookie` + `_` + `hash_hmac('sha256', user_id, app.key)`, обрезанный до 16 символов. Отдельная cookie на пользователя: несколько учёток в одном браузере не мешают друг другу, `user_id` в имени не раскрывается.
- Значение: `Crypt::encryptString(json{uid, v, exp})`. Это шифрование с MAC, независимое от `EncryptCookies`.
- Атрибуты: `HttpOnly`, `Secure` по `config('session.secure')`, `SameSite=Lax`, `path` = префикс Orchid, срок `trusted_devices.lifetime_days`.
- Проверка: расшифровка успешна, `uid` равен пользователю, прошедшему пароль, `v === trusted_devices_version`, `exp > now`. Невалидная cookie удаляется.

### 5.7. События (`Nakipelo\Orchid2FA\Events`)
Все несут `user` и `guard`, дополнительно:
- `TwoFactorChallengeSent` — `channel`, `maskedDestination`, `context` (`login`, `enable`, `disable`);
- `TwoFactorPassed` — `via` (`code`, `trusted_device`), `trustedDeviceIssued`;
- `TwoFactorFailed` — `reason` (`invalid_code`, `expired`, `delivery_failed`);
- `TwoFactorLockedOut` — `reason` (`attempts_exceeded`, `send_limit`), `availableIn`.

Кроме того, финальный вход порождает штатный `Illuminate\Auth\Events\Login`. `LogTwoFactorEvents` пишет все четыре события в `log.channel`, подписывается при `log.enabled`.

### 5.8. Уведомления
`TwoFactorCodeNotification` (`mail`): код, срок, маскированного адреса нет, IP и user-agent не содержит. Класс задаётся в `notification.class` и должен принимать `(string $code, CarbonInterface $expiresAt)`. По умолчанию отправка синхронная. При `notification.queue = true` класс реализует `ShouldQueue` через `connection`/`queue` из конфига. `TwoFactorEmailChangedNotification` уходит через `Notification::route('mail', $old)` и тоже подменяется конфигом.

### 5.9. Код
`random_int` на `code.length` цифр с ведущими нулями. В cache (`cache.store`) по ключу `orchid-2fa:code:{user_id}` лежит `{hash, challenge_id, destination_hash, expires_at}`, TTL `code.ttl`. `hash = hash_hmac('sha256', code.'|'.challenge_id, app.key)`, сравнение через `hash_equals`. Код действителен, только если `challenge_id` совпадает с pending и `destination_hash` — с текущим адресом. Попытки считаются в `RateLimiter` по ключу `orchid-2fa:verify:{user_id}:{challenge_id}`, отправки — `orchid-2fa:send:{user_id}` (час) и `orchid-2fa:cooldown:{user_id}`. Попытка засчитывается до сравнения, это закрывает параллельный перебор. Успешная проверка удаляет запись атомарно (`Cache::pull`).

## 6. UI

- **Экран кода** — `orchid-2fa::challenge`, `@extends` от `Orchid::authLayout()`, публикуется (тег `orchid-2fa-views`). Элементы:
  - поле `code` с `autocomplete="one-time-code"`, `inputmode="numeric"`, `pattern="\d{6}"`, `maxlength`, autofocus;
  - строка «Код отправлен на e***@gmail.com»;
  - галочка `trust_device` (если включено в конфиге);
  - кнопка «Войти»;
  - кнопка «Отправить повторно» с обратным отсчётом: небольшой inline-скрипт, без внешних зависимостей, без JS кнопка просто заблокирована до истечения;
  - кнопка «Войти под другим пользователем».
- **Экран профиля** `TwoFactorProfileScreen`: статус (выключено, включено, обязательно; адрес подтверждён или нет), действия из §4.7. Кнопки «Выключить» у принудительного пользователя нет.
- **Ссылка из профиля** (обязательная): в `layout()` стаба `UserProfileScreen` добавляется `TwoFactorProfileLinkLayout::class` — одна строка, инструкция в README. Layout показывает статус 2FA и кнопку-ссылку на `platform.profile.two-factor`.
- **Пункт основного меню** — опционально, `menu.enabled` (по умолчанию `false`), через `Orchid::registerMenu()`.
- **Сброс в `UserEditScreen`**: в `layout()` добавляется `TwoFactorResetLayout::class`, на экран — `use ResetsTwoFactor;` (метод `resetTwoFactor(User $user)`). Инструкция в README: две строки в стабе.

## 7. Конфиг `config/orchid-2fa.php`

| Ключ | По умолчанию | Назначение |
|---|---|---|
| `enforce_all` | `false` | 2FA обязательна для всех |
| `channel` | `'email'` | канал по умолчанию |
| `channels.email.class` | `EmailChannel::class` | реализация |
| `channels.email.attribute` | `'email'` | атрибут адреса |
| `code.length` | `6` | цифр в коде |
| `code.ttl` | `600` | жизнь кода, с |
| `code.max_attempts` | `5` | неверных вводов на код |
| `resend.cooldown` | `60` | пауза между отправками, с |
| `resend.max_per_hour` | `5` | отправок в час на пользователя |
| `pending_ttl` | `600` | жизнь pending, с |
| `trusted_devices.enabled` | `true` | галочка доверия |
| `trusted_devices.lifetime_days` | `30` | срок cookie |
| `trusted_devices.cookie` | `'orchid_2fa_trusted'` | префикс имени cookie |
| `notification.class` | `TwoFactorCodeNotification::class` | письмо с кодом |
| `notification.email_changed_class` | `TwoFactorEmailChangedNotification::class` | письмо о смене адреса |
| `notification.queue` | `false` | отправлять через очередь |
| `notification.connection` | `null` | соединение очереди |
| `notification.queue_name` | `null` | имя очереди |
| `cache.store` | `null` | store для кодов (null — default) |
| `routes.throttle` | `'10,1'` | throttle по IP для verify/resend |
| `menu.enabled` | `false` | пункт «Двухфакторная аутентификация» в основном меню |
| `log.enabled` | `false` | подписать `LogTwoFactorEvents` |
| `log.channel` | `null` | канал лога (null — default) |

Имена прав в конфиг не выносятся: это публичный контракт, см. §8.

## 8. Права
Пакет регистрирует их через адаптер, группа «Two-factor authentication»:
- `platform.2fa.required` — 2FA обязательна для владельца права;
- `platform.systems.users.2fa-reset` — сброс 2FA другим пользователям (кнопка в `UserEditScreen`; artisan-команда права не проверяет).

`orchid:admin` выдаёт пользователю `Dashboard::getAllowAllPermission()`, то есть и `platform.2fa.required`. Так и задумано: администраторы обязаны проходить 2FA, из «всех прав» право не исключается. В README: при первом входе администратору нужна рабочая почта, иначе вход восстанавливается только через `orchid-2fa:reset` после исправления адреса.

## 9. Безопасность

| Угроза | Защита |
|---|---|
| Вход только по паролю | Логин не происходит до кода, `validate()` вместо `attempt()`. Сессия до кода — гостевая |
| Прямой заход в админку при pending | Пользователь гость, `Access` редиректит на логин. Тест |
| Подмена `user_id` | `user_id` берётся только из серверной сессии. Параметры запроса игнорируются. Тест с `user_id` в POST |
| Фиксация сессии | `regenerate()` при создании pending и при финальном входе |
| Перебор кода | 5 попыток на код, 5 кодов в час → не больше 25 попыток в час против 10⁶ вариантов; throttle по IP; инкремент до сравнения |
| Повтор старого кода | `Cache::pull` при успехе; новый код аннулирует старый; привязка к `challenge_id` |
| Код из другой сессии или старого вызова | `challenge_id` в pending и в hash |
| Утечка кодов из cache | Хранится HMAC на `app.key`, не сам код |
| Смена адреса для перехвата кода | Уведомление на старый адрес, `confirmed_at = null`, код привязан к `destination_hash`. **Принятый остаточный риск:** `UserProfileScreen` Orchid меняет e-mail без пароля, и злоумышленник с украденной сессией перенаправит коды на свой адрес; владельцу придёт только уведомление на старый адрес. Пакет стаб не меняет, README рекомендует подтверждение паролем в стабе |
| Подделка или перенос cookie доверия | Шифрование с MAC, `uid` и `version` сверяются с БД, срок внутри payload, пароль проверяется всё равно |
| Утеря доверенного устройства | «Выйти со всех доверенных устройств», смена пароля |
| Обход при сбое почты | Fail-closed, кнопки «пропустить» нет |
| Перечисление пользователей | Ответ на неверный пароль идентичен Orchid. Лимиты отправки срабатывают только после верного пароля |
| Тайминг | `hash_equals`. Неверный пароль обрабатывается тем же путём, что у Orchid |
| Remember-cookie в обход 2FA | Выдаётся только после 2FA; ротация `remember_token` при включении 2FA; `orchid-2fa:rotate-remember-tokens` для cookie, выданных до установки (§4.5) |
| Выключение 2FA с украденной сессией | Подтверждение кодом на почту; принудительному выключение недоступно, проверка на сервере |
| Вход мимо Orchid в тот же guard | Вне зоны пакета в v0.1, предупреждение в README; защитный middleware — кандидат на v0.2 |
| Замещение `POST login` не сработало | Тест этапа 1, в том числе с `route:cache`; запасной путь через `platform.auth = false` (§5.3). При `platform.auth = false` на основном пути — предупреждение в лог |
| CSRF | Все POST в группе `web`, `@csrf` в формах |

## 10. Тестирование
- Pest и Orchestra Testbench с реальным `orchid/platform`. Workbench содержит стабы Orchid (`App\Models\User` с `HasTwoFactor`, `PlatformProvider`, экраны пользователей), SQLite in-memory, `Mail`/`Notification::fake()` и реальный cache `array`.
- **Интеграционные тесты сквозного входа:**
  - верный код;
  - неверный код;
  - просроченный код;
  - 5 неверных попыток → код аннулирован;
  - повторная отправка: cooldown и лимит в час, обратный отсчёт;
  - доверенное устройство: выдача, пропуск кода, истечение, инкремент версии, чужой `uid`, битая cookie;
  - remember: cookie выдаётся только после кода, повторный визит без кода, lock-cookie;
  - impersonation: `loginAs` и `switch-logout` без кода;
  - пользователь без 2FA входит как в Orchid, включая `redirect()->intended`;
  - события `Attempting`/`Failed` при входе и rehash пароля после `validate()` (на всех трёх версиях Laravel);
  - JSON-ответы;
  - `enforce_all` и право `platform.2fa.required`;
  - fail-closed при исключении транспорта;
  - pending истёк;
  - «войти под другим».
- **Попытки обхода:**
  - GET `platform.index` при pending;
  - повтор использованного кода;
  - код от предыдущего вызова;
  - `user_id` в теле запроса;
  - verify без pending;
  - verify после смены e-mail;
  - параллельные verify;
  - старая remember-cookie после включения 2FA и после `orchid-2fa:rotate-remember-tokens` не пускает;
  - выключение 2FA принудительным пользователем прямым POST отклоняется.
- **Маршруты (этап 1):** `route('platform.login.auth')` и `POST` на его URI попадают в контроллер пакета без кеша и после `route:cache`; `GET platform.login` остаётся за Orchid; при `platform.auth = false` `POST login` не регистрируется и пишется предупреждение в лог.
- **Unit-тесты:** маскирование, `CodeStore`, `TwoFactorPolicy`, `TrustedDeviceCookie`, адаптер (включая имя lock-cookie).
- **Профиль и админка:** включение с ротацией `remember_token`, выключение с кодом, отсутствие кнопки выключения у принудительного, `TwoFactorProfileLinkLayout` в `UserProfileScreen`, пункт меню при `menu.enabled` и его отсутствие по умолчанию, сброс через Layout (с правом и без), `orchid-2fa:reset`, `orchid-2fa:rotate-remember-tokens`, `orchid:admin` → принудительный, смена e-mail и пароля через модель.
- **Статика:** Larastan (level 8, без baseline), Pint (preset `laravel`).
- **CI:** GitHub Actions по матрице §2 с jobs `pint`, `larastan`, `pest`. Зеркало в Gitea (`git.techbooking.ru`, push-mirror).

## 11. Этапы

**1. Каркас.** `composer.json`, провайдер, адаптер, конфиг, миграция и модель, `HasTwoFactor`, workbench (`composer serve` поднимает Orchid с тестовым админом), Pest, Larastan, Pint, CI и зеркало.
Сюда же — регистрация `POST login` на контроллер пакета (на этом этапе заглушка) и обработка `platform.auth = false`.
*Готово, когда:* CI зелёный по матрице; `composer serve` открывает админку Orchid; миграция применяется и откатывается; провайдер с не-`SessionGuard` падает с понятной ошибкой; grep по `src/` находит `platform.`, `platform::` и `Orchid\` только в `Support/Orchid.php` (проверка в CI скриптом); тесты маршрутов §10 проходят на всех версиях матрицы, включая `route:cache`, — либо, если не проходят, выбран и реализован запасной путь §5.3 и §5.3 обновлён.

**2. Вход с кодом.** `LoginController`, pending, `ChallengeManager`, `CodeStore`, `EmailChannel`, notification, экран кода, лимиты, события, логгер, fail-closed.
*Готово, когда:* все сценарии §4.1–4.3, 4.5 (кроме ротации при добровольном включении — этап 4), 4.6, 4.10, 4.11 и тесты обхода из §10 проходят; `Attempting`/`Failed` и rehash проверены на L11–13; ручная проверка в workbench (письмо в лог-мейлер) пройдена; без 2FA вход ничем не отличается от Orchid.

**3. Доверенное устройство.** `TrustedDeviceCookie`, галочка, инкременты версии.
*Готово, когда:* проходят тесты §4.4, включая смену пароля через `UserProfileScreen` и `UserEditScreen` в workbench; при `trusted_devices.enabled = false` галочки нет, а существующие cookie игнорируются.

**4. Профиль и администрирование.** `TwoFactorProfileScreen`, `TwoFactorProfileLinkLayout`, опция `menu.enabled`, выключение с кодом, ротация `remember_token`, `TwoFactorResetLayout` и `ResetsTwoFactor`, право сброса, `orchid-2fa:reset`, `orchid-2fa:rotate-remember-tokens`, смена e-mail.
*Готово, когда:* проходят сценарии §4.5, §4.7–4.9; `TwoFactorProfileLinkLayout` подключён в workbench-стаб `UserProfileScreen` одной строкой, Layout сброса — в стаб `UserEditScreen` двумя строками и работает только с правом; пункта меню нет по умолчанию и он есть при `menu.enabled`; принудительный пользователь не видит кнопку выключения и не может выключить 2FA прямым запросом; `orchid-2fa:reset` сбрасывает 2FA и возвращает ненулевой код для неизвестного e-mail; после `orchid-2fa:rotate-remember-tokens` старые remember-cookie не пускают.

**5. Релиз.** README: установка, шаг «после установки выполните `orchid-2fa:rotate-remember-tokens`», трейт, Layout для `UserProfileScreen` (одна строка) и `UserEditScreen`, конфиг (`menu.enabled`), требования (Laravel от 11.35; L13 — только PHP 8.3+), ограничения и рекомендации: очередь, массовые update, вход в тот же guard мимо Orchid (Breeze/Fortify/свои маршруты) обходит 2FA, `platform.auth = false`, `orchid:admin` делает администратора принудительным — нужна рабочая почта, иначе только `orchid-2fa:reset`, смена e-mail в `UserProfileScreen` без пароля — добавить подтверждение паролем в стаб. Переводы en и ru (публикуемые, тег `orchid-2fa-translations`), CHANGELOG, тег `0.1.0`, Packagist.
*Готово, когда:* чистая установка в свежий Laravel и Orchid по README проходит; все строки UI и писем переведены и без хардкода; первый потребитель обновлён на `^0.1`.

## 12. Открытые вопросы

Открытых вопросов нет: решения внесены в §1–§11.
