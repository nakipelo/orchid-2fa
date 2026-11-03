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
2. Контроллер диспатчит `Illuminate\Auth\Events\Attempting`, затем `guard->validate(email, password)`. `validate()`, в отличие от `attempt()`, не шлёт `Attempting`/`Failed` и не рехеширует пароль, поэтому всё это делает контроллер пакета. При неверном пароле — `Failed` и та же `ValidationException` на `email` с тем же текстом, что у Orchid. При верном — сразу `provider->rehashPasswordIfRequired($user, $credentials)`: после шага кода пароля в запросе уже нет, а хранить его в pending нельзя. Рехеш выполняется, только если `hashing.rehash_on_login` (по умолчанию `true`) — та же настройка, по которой `SessionGuard::attempt()` решает, рехешировать ли (свойство guard защищённое, поэтому читается конфиг). API `UserProvider::rehashPasswordIfRequired()` одинаков в Laravel 11.35–13; проверено тестами.
3. 2FA не требуется → шаг «финальный вход» (§4.3).

### 4.2. Вход с 2FA
1. Пункты 1–2 из §4.1.
2. 2FA требуется, доверенного устройства нет (§4.4) → `session()->regenerate()`, в сессию кладётся pending (ключ `orchid-2fa.pending`).
3. Если для пользователя уже есть активный код (не истёк, попытки остались, привязан к текущему адресу), новый не отправляется, а pending получает `challenge_id` этого кода. Иначе выпускается и отправляется новый код (§4.9, §4.10), старый аннулируется. `challenge_id` выдаётся на код (новый при каждой отправке), pending хранит `challenge_id` своего кода; «Отправить повторно» обновляет его в pending. Если код отправить нельзя (лимит §4.11 или ошибка §4.10), pending всё равно создаётся (с `challenge_id`, которому код не соответствует), а экран кода показывает ошибку; срок pending повторная отправка не продлевает.
4. Редирект на `platform.two-factor.challenge`. Для `wantsJson()` — `200 {"two_factor": true, "redirect": "<url>"}`.
5. Экран кода. При `POST platform.two-factor.verify`:
   - pending нет или истёк → редирект на `platform.login` с сообщением «сессия входа истекла»;
   - кода для этого `challenge_id` нет (истёк, использован, заменён новым, адрес изменился) → `TwoFactorFailed(reason: expired)`, сообщение «код больше недействителен, запросите новый»;
   - код неверный → `TwoFactorFailed(reason: invalid_code)`, попытка засчитана, сообщение с числом оставшихся попыток; на 5-й неверной — `TwoFactorFailed(invalid_code)` и `TwoFactorLockedOut(attempts_exceeded)`, код аннулируется, сообщение «код больше недействителен, запросите новый»;
   - код верный → код удаляется из cache, pending удаляется, при первом успехе выставляется `confirmed_at`, при отмеченной галочке выдаётся cookie доверия (§4.4), `TwoFactorPassed`, финальный вход (§4.3).
6. «Войти под другим пользователем» (`POST platform.two-factor.cancel`) удаляет pending, забывает lock-cookie и редиректит на `platform.login`. Активный код при этом не удаляется.
7. JSON (`wantsJson()`) на шаге кода: ошибки verify и resend, а также отсутствие/истечение pending — `422` с ошибкой на поле `code`; успешный verify — `204` (§4.3); успешный resend — `200 {"resend_available_in": N}`.

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
- *Уточнение этапа 4:* команда обновляет запросом query builder без глобальных scope (`newQueryWithoutScopes()->toBase()`, `WHERE remember_token IS NOT NULL`), поэтому `updated_at` и события модели не затрагиваются; колонка — `getRememberTokenName()` модели. Отказ в подтверждении (и запуск без `--force` с `--no-interaction`) — код возврата 1, ничего не меняется.

### 4.6. Impersonation
`Orchid\Access\Impersonation::loginAs()` / `logout()` работают через `loginUsingId` и маршрут логина не затрагивают, поэтому 2FA не спрашивается. Пакет в них не вмешивается. Тест фиксирует это поведение.

### 4.7. Включение и выключение в профиле (`platform.profile.two-factor`)
- **Вход на экран**: Layout `TwoFactorProfileLinkLayout` на `UserProfileScreen` (кнопка-ссылка со статусом, подключается одной строкой в `layout()` стаба, §6). Пункт в основном меню — только при `menu.enabled` (по умолчанию выключен): меню профиля в Orchid 14 нет, `registerProfileMenu()` помечен `@deprecated` и сливается в общее меню.
- **Включить** (для добровольного пользователя): «Отправить код» → код на текущий e-mail (те же лимиты) → ввод → `enabled_at = confirmed_at = now()`, `channel = email`, ротация `remember_token` (§4.5). Без верного кода 2FA не включается.
- **Выключить**: доступно только добровольному и подтверждается кодом на текущий e-mail (тот же поток и лимиты, что при включении). Выставляет `enabled_at = null`, `confirmed_at = null` и инкрементирует `trusted_devices_version`. Принудительный пользователь видит статус «обязательно для вашей учётной записи» без кнопки выключения; сервер повторно проверяет `TwoFactorPolicy::isEnforced()` и отклоняет запрос на выключение (отправку кода и подтверждение) от принудительного пользователя.
- **Выйти со всех доверенных устройств**: инкремент `trusted_devices_version`, кнопка доступна при любом статусе.
- Принудительному пользователю запись в таблице создаётся лениво, при первом вызове (с ротацией `remember_token`, §4.5). `confirmed_at` выставляется при первом успешном коде.
- *Уточнения этапа 4:*
  - Методы экрана (Orchid, `POST profile/two-factor/{method}`): `sendEnableCode`, `enable`, `sendDisableCode`, `disable`, `cancelCode`, `forgetTrustedDevices`. GET с методом Orchid перенаправляет на экран, действие не выполняется; CSRF — штатный, группа `web`.
  - Отправленный из профиля код запоминается в сессии (`orchid-2fa.profile`: `user_id`, `action` = `enable`/`disable`, `challenge_id`) и подтверждает только своё действие и только своего пользователя. Код другого вызова (например, входа в другой сессии) не принимается. «Отправить код повторно» на шаге кода — тот же `sendEnableCode`/`sendDisableCode`: новый код аннулирует прежний (код у пользователя один на вход и профиль, §5.9), действуют cooldown и часовой лимит. «Отмена» закрывает шаг кода, сам код не удаляется (как «войти под другим»).
  - Неверный код — ошибка валидации на `code` с числом оставшихся попыток; код истёк, попытки исчерпаны или код не запрашивался — toast «код больше недействителен, запросите новый», шаг кода закрывается. Ошибка отправки и лимиты — toast с теми же текстами, что на экране кода.
  - Принудительному пользователю сервер отвечает `403` и на выключение, и на включение (включение тоже только для добровольного). Устаревший запрос без принуждения (включить уже включённое, выключить невключённое) — toast-предупреждение без изменений.
  - Событие `TwoFactorChallengeSent` с `context` `enable`/`disable`; `TwoFactorPassed` в профиле не порождается (это событие входа). Отдельных событий включения, выключения и сброса в v0.1 нет (§5.7).

### 4.8. Сброс администратором
- `UserEditScreen`: Layout пакета с кнопкой «Сбросить 2FA». Видна при праве `platform.systems.users.2fa-reset`.
- `php artisan orchid-2fa:reset {email}`: та же операция, с подтверждением; `--force` подтверждение пропускает.
- Операция сброса: `enabled_at = null`, `confirmed_at = null`, инкремент `trusted_devices_version`, удаление активного кода и счётчиков. Для принудительного пользователя это значит, что следующий вход снова выдаст вызов на текущий e-mail. Это и есть аварийный доступ v0.1: администратор исправляет адрес в карточке пользователя и сбрасывает 2FA. Других обходов нет.
- *Уточнения этапа 4:* «счётчики» — попытки ввода активного кода, часовой лимит отправок и cooldown (`ChallengeManager::clear()`), поэтому после сброса код уходит сразу. Нет записи — она не создаётся. Событий сброс не порождает (§5.7). Сигнатура метода трейта — `resetTwoFactor(TwoFactorManager $manager, mixed $user = null)`, а не `resetTwoFactor(User $user)`: трейт не знает класс модели приложения, а неявная привязка по абстрактному `Model` невозможна. `$user` — параметр маршрута `{user}` (модель при явной привязке или ключ; тогда пользователь берётся через провайдер guard). Право проверяется на сервере: без него `403`, неизвестный пользователь — `404`. Layout скрыт без права и для несохранённого пользователя (экран создания). Команда ищет пользователя через `retrieveByCredentials(['email' => …])` провайдера guard (как при входе); неизвестный e-mail — сообщение и код возврата 1; отказ в подтверждении — код 1.

### 4.9. Смена e-mail при включённом 2FA
- Изменение `email` у модели (профиль, `UserEditScreen`, любой `save()`) ловит трейт `HasTwoFactor`.
- На старый адрес уходит `TwoFactorEmailChangedNotification`. 2FA не выключается. `confirmed_at = null`, активный код аннулируется.
- Следующий вход шлёт код на новый адрес. Успех подтверждает адрес (`confirmed_at = now()`).
- Массовые `update()` через query builder событий модели не вызывают, и уведомление в этом случае не уходит (ограничение описано в README).
- *Уточнения этапа 4:* слушатель реагирует на атрибут `channels.email.attribute`. Код аннулируется и `confirmed_at` обнуляется у любой существующей записи; уведомление уходит, только если 2FA пользователю требуется (принудительный или добровольный) и старый адрес не пуст. Запись не создаётся, `trusted_devices_version` не меняется: cookie доверия не действуют, пока `confirmed_at = null` (§5.6), и снова действуют после подтверждения нового адреса. Ошибка отправки уведомления пишется в лог (`error`, `log.channel`) и не срывает `save()`: адрес уже сохранён. Логика — `TwoFactorManager::addressChanged()`.
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
  Challenge/StoredCode.php, VerificationResult.php  запись кода в cache, итог проверки
  Exceptions/{DeliveryFailedException,SendLimitExceededException}.php
  Http/Controllers/Concerns/CompletesLogin.php     финальный вход (§4.3)
  Policy/TwoFactorPolicy.php              requires()/isEnforced()/isEnabled()
  TrustedDevice/TrustedDeviceCookie.php
  Http/Controllers/LoginController.php    POST platform.login.auth
  Http/Controllers/ChallengeController.php show/verify/resend/cancel
  TwoFactorManager.php                    включение/выключение/сброс, смена e-mail, ротация remember_token
  Challenge/ProfileChallenge.php          код, запрошенный в профиле (сессия `orchid-2fa.profile`)
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
lang/{en,ru}/messages.php                  переводы, namespace orchid-2fa (публикуются в lang/vendor/orchid-2fa)
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
| `pathPrefix()` | путь префикса Orchid (`/admin`; без префикса — `/`), `path` cookie доверия (§5.6) |
| `guestMiddleware()` | `RedirectIfAuthenticated` с `redirectUsing(fn () => indexUrl())`, как в Orchid |
| `registerPermissions(...)`, `registerMenu(...)` | `Dashboard::registerPermissions(ItemPermission)`, `Dashboard::registerMenuElement(Menu)` |
| `loginRoutesEnabled()` | `config('platform.auth', true)` |
| `resetPermission()`, `profileTwoFactorRoute()` | `platform.systems.users.2fa-reset`, `platform.profile.two-factor` |
| `registerProfileScreen(...)` | `Route::screen()` в private-группе, хлебные крошки «Главная › Профиль › 2FA» |
| `toast($message, $level)` | `Orchid\Support\Facades\Toast` |

*Уточнение этапа 4 (UI-слой):* экраны и Layout'ы обязаны наследовать `Orchid\Screen\Screen` / `Orchid\Screen\Layouts\Block` и строить поля и действия классами Orchid, поэтому `src/Screens/` и `src/Layouts/` могут импортировать классы `Orchid\…`. Строки `platform.` и `platform::` (имена маршрутов, прав, конфига, view) запрещены и там — только через адаптер. Остальной `src/` (включая `Concerns/ResetsTwoFactor.php`) по-прежнему без `Orchid\`. Это проверяет `bin/check-adapter.php`. `registerMenu()` перед `Menu::route()` обновляет индекс имён маршрутов: `route()` вызывается сразу, а маршрут, получивший имя после добавления в коллекцию, без этого не находится.

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

Throttle `verify`/`resend` регистрируется как `throttle:{max},{minutes},orchid-2fa`: собственный префикс отделяет счётчик от `throttle:60,1` у `POST login`, у которого та же сигнатура (домен + IP).

Замещение `POST login`: маршрут регистрируется в `$this->app->booted()`, после маршрутов Orchid (Orchid грузит их в booted-колбэке своего `RouteServiceProvider`). В `RouteCollection` маршрут с тем же методом, доменом и URI, добавленный позже, замещает ранний, имя `platform.login.auth` указывает на него. `GET platform.login` не переопределяется. Работоспособность замещения проверяется тестом на этапе 1 (§10, §11): `route('platform.login.auth')` и реальный `POST` на этот URI попадают в контроллер пакета — и без кеша, и после `route:cache`.

**Запасной путь** — если тест этапа 1 не проходит: снимать маршрут Orchid из `RouteCollection` не будем (внутренний API). Вместо этого приложение ставит `platform.auth = false`, а пакет сам регистрирует все маршруты входа Orchid (`routes/auth.php`) под теми же именами и URI, с `POST login` на свой контроллер. Выбор пути фиксируется в этом разделе по итогам этапа 1; при запасном пути меняются шаг установки в README и поведение при `platform.auth = false` (ниже).

**Итог этапа 1: основной путь.** Тесты замещения (`tests/Feature/LoginRouteTest.php`) проходят на Laravel 11, 12 и 13 без кеша и после реального `route:cache` (отдельный процесс `testbench route:cache`, приложение перезагружается из файла кеша); запасной путь не понадобился.

**`config('platform.auth') === false`** (основной путь): Orchid свои маршруты входа не регистрирует, пакет тоже не подменяет `POST login` и в окружениях `local`/`testing` пишет предупреждение в лог (`warning`, один раз при загрузке); в остальных окружениях (в том числе `production`) предупреждения нет — поведение описано в README. Маршруты экрана кода и профиля регистрируются как обычно.

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

Инкремент версии без трейта — `TwoFactorAuthentication::bumpTrustedDevicesVersionFor($userId)` (им же пользуется `bumpTrustedDevicesVersion()`): для кнопки «Выйти со всех доверенных устройств», сброса и выключения (этап 4). Нет записи — нет и cookie доверия, запись не создаётся.

Без трейта провайдер работает, но доверенные устройства не сбрасываются при смене пароля. При загрузке в `local`/`testing` провайдер пишет предупреждение.

### 5.6. Cookie доверенного устройства
- Имя: `trusted_devices.cookie` + `_` + `hash_hmac('sha256', guard.'|'.user_id, app.key)`, обрезанный до 16 символов. Отдельная cookie на пользователя и guard: несколько учёток в одном браузере не мешают друг другу, `user_id` в имени не раскрывается.
- Значение: `Crypt::encryptString(json{uid, g, v, exp})`, `g` — имя guard Orchid. Это шифрование с MAC, независимое от `EncryptCookies` (в группе `web` она шифрует значение ещё раз). Cookie другого приложения (другой `app.key`) не расшифровывается.
- Атрибуты: `HttpOnly`, `SameSite=Lax`, `path` = префикс Orchid (`Orchid::pathPrefix()`), `domain` = `session.domain`, срок `trusted_devices.lifetime_days` (не меньше 1). `Secure` = `session.secure`; если он не задан (`null`, по умолчанию), — по схеме запроса (HTTPS → `Secure`).
- Проверка: расшифровка успешна, `uid` равен пользователю, прошедшему пароль, `g` — текущий guard Orchid, `v === trusted_devices_version` (целое), `exp > now`; запись 2FA существует и `confirmed_at` не null (после смены e-mail, §4.9, вход шлёт код на новый адрес и cookie не действует до подтверждения). Невалидная cookie удаляется.
- При `trusted_devices.enabled = false` галочки нет, cookie не выдаются и не принимаются, но и не удаляются: после повторного включения действующие cookie снова работают.

### 5.7. События (`Nakipelo\Orchid2FA\Events`)
Все несут `user` и `guard`, дополнительно:
- `TwoFactorChallengeSent` — `channel`, `maskedDestination`, `context` (`login`, `enable`, `disable`);
- `TwoFactorPassed` — `via` (`code`, `trusted_device`), `trustedDeviceIssued`;
- `TwoFactorFailed` — `reason` (`invalid_code`, `expired`, `delivery_failed`);
- `TwoFactorLockedOut` — `reason` (`attempts_exceeded`, `send_limit`), `availableIn`.

Кроме того, финальный вход порождает штатный `Illuminate\Auth\Events\Login`. `LogTwoFactorEvents` пишет все четыре события в `log.channel`, подписывается при `log.enabled`.

### 5.8. Уведомления
`TwoFactorCodeNotification` (`mail`): код, срок, маскированного адреса нет, IP и user-agent не содержит. Класс задаётся в `notification.class` и должен принимать `(string $code, CarbonInterface $expiresAt)`. По умолчанию отправка синхронная (`Notification::sendNow`, даже если класс реализует `ShouldQueue`). При `notification.queue = true` `EmailChannel` сам ставит в очередь `SendQueuedNotifications` с `connection`/`queue_name` из конфига, поэтому класс не обязан реализовывать `ShouldQueue`. Письмо адресуется через `AnonymousNotifiable` на адрес из `channels.email.attribute`, трейт `Notifiable` у модели не нужен. Нет адреса → `DeliveryFailedException` (fail-closed, §4.10). `TwoFactorEmailChangedNotification` уходит через `Notification::route('mail', $old)` и тоже подменяется конфигом (`notification.email_changed_class`); класс должен принимать `(string $maskedNewAddress)`, новый адрес в письме только маскированный. *Уточнение этапа 4:* отправка — через `EmailChannel::notify()` с теми же `notification.queue`/`connection`/`queue_name`, что и письмо с кодом.

### 5.9. Код
`random_int` на `code.length` цифр с ведущими нулями. В cache (`cache.store`) по ключу `orchid-2fa:code:{user_id}` лежит `{hash, challenge_id, destination_hash, expires_at}`, TTL `code.ttl`. `hash = hash_hmac('sha256', code.'|'.challenge_id, app.key)`, сравнение через `hash_equals`. Код действителен, только если `challenge_id` совпадает с pending и `destination_hash` — с текущим адресом. Попытки считаются в `RateLimiter` по ключу `orchid-2fa:verify:{user_id}:{challenge_id}`, отправки — `orchid-2fa:send:{user_id}` (час) и `orchid-2fa:cooldown:{user_id}`. Попытка засчитывается до сравнения, это закрывает параллельный перебор. Успешная проверка «забирает» код атомарно: `Cache::add('orchid-2fa:used:{user_id}:{challenge_id}')` (атомарен в штатных store Laravel, в отличие от `Cache::pull` = get + forget), затем запись удаляется; второй параллельный verify с тем же кодом получает отказ.

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
- **Сброс в `UserEditScreen`**: в `layout()` добавляется `TwoFactorResetLayout::class`, на экран — `use ResetsTwoFactor;` (метод `resetTwoFactor`, сигнатура — §4.8). Инструкция в README: две строки в стабе.
- *Уточнение этапа 4:* оба Layout'а — `Block` в стиле стабов Orchid 14 (заголовок и описание слева, карточка со статусом справа, кнопки внизу). `TwoFactorResetLayout` берёт пользователя из `user` запроса экрана, показывает статус («обязательна», «включена пользователем», «выключена») и адрес (подтверждён или нет); кнопка «Сбросить 2FA» — с подтверждением. Экран профиля: блок статуса (кнопка «Включить» или «Выключить»), блок шага кода (поле `code` с `autocomplete="one-time-code"`, «Подтвердить», «Отправить код повторно», «Отмена»), блок «Доверенные устройства». Пункт меню при `menu.enabled` — «Двухфакторная аутентификация», иконка `bs.shield-lock`, без права.

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

Регистрация — в `booted`, вместе с маршрутами. На этапе 2 регистрируется только `platform.2fa.required` (без неё `getAllowAllPermission()` его не содержит и администратор не становится принудительным); `platform.systems.users.2fa-reset` — на этапе 4 вместе с кнопкой сброса (`orchid:admin` получает и его). Кнопке сброса нужен ещё и доступ к самому `UserEditScreen` (`platform.systems.users` в стабе).

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
| Код из другой сессии или старого вызова | `challenge_id` в pending и в hash. Уточнение: из-за переиспользования активного кода (§4.2 п. 3) другая сессия того же пользователя, прошедшая пароль, пока код активен, получает тот же `challenge_id`, и код действует в ней тоже; сессия со старым `challenge_id` код не примет |
| Утечка кодов из cache | Хранится HMAC на `app.key`, не сам код |
| Смена адреса для перехвата кода | Уведомление на старый адрес, `confirmed_at = null`, код привязан к `destination_hash`. **Принятый остаточный риск:** `UserProfileScreen` Orchid меняет e-mail без пароля, и злоумышленник с украденной сессией перенаправит коды на свой адрес; владельцу придёт только уведомление на старый адрес. Пакет стаб не меняет, README рекомендует подтверждение паролем в стабе |
| Подделка или перенос cookie доверия | Шифрование с MAC, `uid`, guard и `version` сверяются, срок внутри payload, пароль проверяется всё равно |
| Утеря доверенного устройства | «Выйти со всех доверенных устройств», смена пароля |
| Обход при сбое почты | Fail-closed, кнопки «пропустить» нет |
| Перечисление пользователей | Ответ на неверный пароль идентичен Orchid. Лимиты отправки срабатывают только после верного пароля |
| Тайминг | `hash_equals`. Неверный пароль обрабатывается тем же путём, что у Orchid |
| Remember-cookie в обход 2FA | Выдаётся только после 2FA; ротация `remember_token` при включении 2FA; `orchid-2fa:rotate-remember-tokens` для cookie, выданных до установки (§4.5) |
| Выключение 2FA с украденной сессией | Подтверждение кодом на почту; принудительному выключение недоступно, проверка на сервере |
| Вход мимо Orchid в тот же guard | Вне зоны пакета в v0.1, предупреждение в README; защитный middleware — кандидат на v0.2 |
| Замещение `POST login` не сработало | Тест этапа 1, в том числе с `route:cache`; запасной путь через `platform.auth = false` (§5.3). При `platform.auth = false` на основном пути — предупреждение в лог в `local`/`testing` |
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
- **Маршруты (этап 1):** `route('platform.login.auth')` и `POST` на его URI попадают в контроллер пакета без кеша и после `route:cache`; `GET platform.login` остаётся за Orchid; при `platform.auth = false` `POST login` не регистрируется, в `testing` пишется предупреждение в лог, в `production` — нет.
- **Unit-тесты:** маскирование, `CodeStore`, `TwoFactorPolicy`, `TrustedDeviceCookie`, адаптер (включая имя lock-cookie).
- **Профиль и админка:** включение с ротацией `remember_token`, выключение с кодом, отсутствие кнопки выключения у принудительного, `TwoFactorProfileLinkLayout` в `UserProfileScreen`, пункт меню при `menu.enabled` и его отсутствие по умолчанию, сброс через Layout (с правом и без), `orchid-2fa:reset`, `orchid-2fa:rotate-remember-tokens`, `orchid:admin` → принудительный, смена e-mail и пароля через модель.
- **Статика:** Larastan (level 8, без baseline), Pint (preset `laravel`).
- **CI:** GitHub Actions по матрице §2 с jobs `pint`, `larastan`, `pest`. Зеркало в Gitea (`git.techbooking.ru`, push-mirror).

## 11. Этапы

**1. Каркас.** `composer.json`, провайдер, адаптер, конфиг, миграция и модель, `HasTwoFactor`, workbench (`composer serve` поднимает Orchid с тестовым админом), Pest, Larastan, Pint, CI и зеркало.
Сюда же — регистрация `POST login` на контроллер пакета (на этом этапе заглушка) и обработка `platform.auth = false`.
*Готово, когда:* CI зелёный по матрице; `composer serve` открывает админку Orchid; миграция применяется и откатывается; провайдер с не-`SessionGuard` падает с понятной ошибкой; grep по `src/` находит `platform.`, `platform::` и `Orchid\` только в `Support/Orchid.php` (проверка в CI скриптом); тесты маршрутов §10 проходят на всех версиях матрицы, включая `route:cache`, — либо, если не проходят, выбран и реализован запасной путь §5.3 и §5.3 обновлён.

**2. Вход с кодом.** `LoginController`, pending, `ChallengeManager`, `CodeStore`, `EmailChannel`, notification, экран кода, лимиты, события, логгер, fail-closed.
*Итог этапа 2:* реализовано (до ревью); тесты — `tests/Feature/Login/*`, `tests/Feature/Unit/ComponentsTest.php`; галочки доверия на экране кода нет до этапа 3. Уточнения зафиксированы в §4.1, §4.2, §5, §5.3, §5.8, §5.9, §8, §9.
*Готово, когда:* все сценарии §4.1–4.3, 4.5 (кроме ротации при добровольном включении — этап 4), 4.6, 4.10, 4.11 и тесты обхода из §10 проходят; `Attempting`/`Failed` и rehash проверены на L11–13; ручная проверка в workbench (письмо в лог-мейлер) пройдена; без 2FA вход ничем не отличается от Orchid.

**3. Доверенное устройство.** `TrustedDeviceCookie`, галочка, инкременты версии.
*Готово, когда:* проходят тесты §4.4, включая смену пароля через `UserProfileScreen` и `UserEditScreen` в workbench; при `trusted_devices.enabled = false` галочки нет, а существующие cookie игнорируются.
*Итог этапа 3:* реализовано (до ревью); тесты — `tests/Feature/Login/TrustedDeviceTest.php`, `tests/Feature/Unit/TrustedDeviceCookieTest.php`. Слушатель смены пароля в `HasTwoFactor` — на этом этапе; кнопка «Выйти со всех доверенных устройств», выключение и сброс (их инкременты) — этап 4, API инкремента готов (§5.5). Уточнения зафиксированы в §5.1, §5.5, §5.6, §9.

**4. Профиль и администрирование.** `TwoFactorProfileScreen`, `TwoFactorProfileLinkLayout`, опция `menu.enabled`, выключение с кодом, ротация `remember_token`, `TwoFactorResetLayout` и `ResetsTwoFactor`, право сброса, `orchid-2fa:reset`, `orchid-2fa:rotate-remember-tokens`, смена e-mail.
*Итог этапа 4:* реализовано (до ревью); тесты — `tests/Feature/Profile/*`, `tests/Feature/Admin/*`, `tests/Feature/EmailChangeTest.php`, `tests/MenuEnabled/*`, маршрут профиля после `route:cache` — в `tests/Feature/LoginRouteTest.php`. Уточнения зафиксированы в §4.5, §4.7–4.9, §5, §5.1, §5.8, §6, §8.
*Готово, когда:* проходят сценарии §4.5, §4.7–4.9; `TwoFactorProfileLinkLayout` подключён в workbench-стаб `UserProfileScreen` одной строкой, Layout сброса — в стаб `UserEditScreen` двумя строками и работает только с правом; пункта меню нет по умолчанию и он есть при `menu.enabled`; принудительный пользователь не видит кнопку выключения и не может выключить 2FA прямым запросом; `orchid-2fa:reset` сбрасывает 2FA и возвращает ненулевой код для неизвестного e-mail; после `orchid-2fa:rotate-remember-tokens` старые remember-cookie не пускают.

**5. Релиз.** README: установка, шаг «после установки выполните `orchid-2fa:rotate-remember-tokens`», трейт, Layout для `UserProfileScreen` (одна строка) и `UserEditScreen`, конфиг (`menu.enabled`), требования (Laravel от 11.35; L13 — только PHP 8.3+), ограничения и рекомендации: очередь, массовые update, вход в тот же guard мимо Orchid (Breeze/Fortify/свои маршруты) обходит 2FA, `platform.auth = false`, `orchid:admin` делает администратора принудительным — нужна рабочая почта, иначе только `orchid-2fa:reset`, смена e-mail в `UserProfileScreen` без пароля — добавить подтверждение паролем в стаб. Переводы en и ru (публикуемые, тег `orchid-2fa-translations`), CHANGELOG, тег `0.1.0`, Packagist.
*Готово, когда:* чистая установка в свежий Laravel и Orchid по README проходит; все строки UI и писем переведены и без хардкода; первый потребитель обновлён на `^0.1`.

## 12. Открытые вопросы

Открытых вопросов нет: решения внесены в §1–§11.
