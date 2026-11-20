# control-plane

API кластера Fugu Deck, доступный из интернета. Поэтому прав у него почти нет: ключей API он не видит, подписи действий
не проверяет и подменить не может — это делает keyguard. Архитектура — [публичная документация](https://github.com/stevv1e/fugu-deck-app/blob/main/docs/TECHNICAL_ARCHITECTURE.md).

**Готово (0.11.x, две реплики):** вход по приглашению; Windows pairing по коду; вход на `api.<домен>` (сертификат
устройства + токен + DPoP; отозванное устройство не пускается сразу — список keyguard, D63); ключи API, лимиты, MCP и
домены для агента (подписанные действия — в keyguard как есть); личные и общие пространства, участники, спонсорство;
устройства и приглашения из приложения, «Потерян» (удаление старых passkey, D64); серверы для агента (ssh-gateway);
сон пространств, push (FCM), удаление аккаунта, уборка неактивных. Общее для реплик — в Postgres (D73).
**Нет:** состав общего пространства, целиком подписанный владельцем (подписан каждый `role_change`).

| Порт | Кто ходит | Что |
|---|---|---|
| 8080 | Traefik: `join.<домен>`, `api.<домен>` | `GET /start` — проверить приглашение, поставить cookie, увести в Keycloak; `POST /v1/enroll/challenge`, `/v1/enroll`, `/v1/enroll/status` — передаются в keyguard как есть |
| 8080 | Traefik: только `api.<домен>` (mTLS) | `GET /v1/me`; `POST /v1/keys` — шифротекст ключа API и подписанное действие передаются в keyguard как есть |
| 8080 | Traefik: только `api.<домен>` (mTLS) | `GET`/`POST /v1/space` — состояние и создание личного пространства (объект `Space`, остальное делает space-operator); `/s/<ник>/…` — запрос уходит агенту пространства с коротким токеном control-plane, потоковые ответы не буферизуются |
| 8080 | Traefik: только `api.<домен>` (mTLS) | `GET /v1/devices` — устройства пользователя (администратору — всех) из реестра keyguard; `POST /v1/devices/confirm`, `/v1/devices/revoke` — подписанное действие передаётся в keyguard как есть; `POST /v1/invites` — подписанное действие `invite_create`: подпись и право приглашать проверяет keyguard, ник берётся из действия |
| 8080 | `join` / `api` (mTLS для подтверждения) | Windows pairing: `POST /v1/pair/start` по приглашению создаёт код на 15 минут; `POST /v1/pair/lookup` находит ПК по коду; `POST /v1/pair/approve` проверяет `pair_approve` через keyguard. Секрет pairing хранится только как SHA-256 |
| 8080 | Traefik: только `api.<домен>` (mTLS) | `POST /v1/space/delete` — подписанное действие `space_delete` записывается в `Space` (`deleteRequestedAt`, `deleteSignature`); подпись проверяет и срок отсчитывает space-operator. `POST /v1/space/restore` — отмена до истечения срока |
| 8080 | Traefik: только `api.<домен>` (mTLS) | Общие пространства: `GET /v1/spaces` — личное и общие, где пользователь участник; `POST /v1/spaces {"title"}` — создать; `GET /v1/spaces/<id>` — состояние и участники; `POST …/members` — подписанное владельцем `role_change` (проверяет keyguard); `POST …/wake`, `…/delete`, `…/restore`. `/s/<t-id>/…` — вход участника с его ролью; состав и исключение передаются агенту (`/internal/roster`, `/internal/revoke`) |
| 8080 | Traefik: только `api.<домен>` (mTLS) | Спонсорство: `POST /v1/grants`, `POST /v1/grants/revoke` — подписанные спонсором `grant` и `grant_revoke` уходят в keyguard как есть (только для пространства, где подписавший состоит) |
| 8080 | Traefik: только `api.<домен>` (mTLS) | Серверы для агента: `GET /v1/ssh` — серверы, права, ключ CA; `POST /v1/ssh/servers`, `/v1/ssh/rights` — подписанные `server_add` и `agent_rights` уходят в ssh-gateway как есть; `POST /v1/ssh/servers/remove`. Выполнять команды control-plane не может |
| 8080 | Traefik: только `api.<домен>` (mTLS) | Ключи и расходы: `POST /v1/keys/delete`, `/v1/limits`, `GET /v1/keys/status`; MCP-серверы: `POST /v1/mcp`, `/v1/mcp/delete`, `GET /v1/mcp/list`; домены для агента: `POST /v1/egress`, `GET /v1/egress/list` — подписанные действия в keyguard как есть |
| 8080 | Traefik: только `api.<домен>` (mTLS) | `POST /v1/push/token` — токен FCM устройства; `POST /v1/account/delete` — подписанное `account_delete`; `GET /v1/app` — последняя версия приложения (`DECK_APP_LATEST`); `GET /v1/ssh/journal`, `POST /v1/ssh/pause` — журнал команд и остановка агента на серверах |
| — | фоновый проход раз в минуту | сон пространств: готовое пространство без обращений дольше `DECK_SLEEP_AFTER` (и без идущего задания — `busy` в `/api/health` агента) получает `spec.suspended: true`; запрос владельца в `/s/<ник>/…` или `POST /v1/space` снимает флаг и отвечает 503 с `Retry-After`. При нескольких репликах проход (и опрос очередей уведомлений) ведёт одна — держащая advisory lock в Postgres; активность пространств видна всем репликам (D73) |
| 8081 | Traefik (forwardAuth) | `/auth/invite` — действует ли приглашение (заголовок `X-Deck-Invite` или cookie `deck_invite`); отдаёт ник в `X-Deck-Invite-Nick` и состояние Windows pairing в `X-Deck-Pair-Status` (`none`/`pending`/`approved`/`invalid`) |
| 8082 | Traefik: `cp.admin.<домен>` (VPN + сертификат администратора) | `POST /admin/v1/invites {"nick": "anna"}` → ссылка `fugudeck://join?…` для QR |

Приглашение: 32 случайных байта, 24 часа, одноразовое, привязано к нику; в базе только хеш. Под приглашение в Keycloak
создаётся пользователь без пароля с обязательной регистрацией passkey.

```bash
go test -race ./...            # тесты сервиса
scripts/keycloak_test.sh       # настоящий Keycloak в контейнере: создание пользователя и границы прав
```

Настройки — переменные окружения (`kubernetes/deck/services/control-plane.yaml`): `DECK_DOMAIN`,
`DECK_HPKE_PUBLIC`, `DECK_DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DECK_KEYGUARD_URL`, `DECK_KEYCLOAK_URL`,
`KEYCLOAK_CLIENT_SECRET`. `DECK_STATE=memory` — без Postgres, только для стендов (и только одна реплика).
Общее состояние реплик на настоящем Postgres: `DECK_TEST_PG=postgres://… go test -run TestPGShared .`
