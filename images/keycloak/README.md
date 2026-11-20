# deck-keycloak

Keycloak с модулем `deck-invite` — первый вход по приглашению без почты (`docs/ARCHITECTURE-v2.md`, 3.3 и 4).

Keycloak выдаёт ссылку на регистрацию passkey только письмом. Модуль добавляет в поток входа шаг `deck-invite`:
если запрос пришёл с приглашением (заголовок `X-Deck-Invite-Nick` ставит Traefik по ответу control-plane) и у
приглашённого ещё нет passkey, он попадает на регистрацию passkey. Пользователя с passkey приглашение не впускает —
он входит как обычно. Исключение для Windows — pairing по коду: control-plane передаёт `X-Deck-Pair-Status: pending`
(страница ожидания) или `approved` после подписанного на телефоне `pair_approve`; approved завершает обычный OAuth flow.
Заголовкам можно верить, потому что клиент их подставить не может: Traefik перезаписывает их ответом forwardAuth.

- `provider/` — исходники модуля (Java 21, Maven). Версия Keycloak в `pom.xml` и в `Dockerfile` — одна и та же.
- `theme/fugu/` — экраны регистрации и входа с явным выбором: это устройство (Windows Hello/PIN/биометрия) или другой телефон/USB-ключ. При регистрации используются WebAuthn `platform`/`cross-platform`, при входе — стандартные hints `client-device` и `hybrid`/`security-key`.
- `Dockerfile` — собирает модуль, тему и оптимизированный образ Keycloak с теми же параметрами сборки, что задаёт оператор.
- `test.sh` — проверка на настоящем Keycloak с realm из `kubernetes/platform/keycloak/realms.yaml` (идёт в CI).

Образ `ghcr.io/<владелец>/deck-keycloak:<версия Keycloak>` собирает и подписывает `.github/workflows/platform-images.yaml`.
Обновление Keycloak: поменять версию в `Dockerfile` (две строки `FROM`), `provider/pom.xml`, `platform-images.yaml` и в
`kubernetes/platform/keycloak/keycloak.yaml`, затем прогнать `test.sh`.
