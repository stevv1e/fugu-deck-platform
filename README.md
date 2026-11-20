# Fugu Deck Platform

Публичный серверный исходный код Fugu Deck и подписанные container images. Репозиторий создан с чистой историей: реальные домены, IP, device ID, приглашения и deployment-секреты владельца сюда не переносятся.

## Компоненты

| Каталог | Образ | Назначение |
|---|---|---|
| `control-plane/` | `ghcr.io/stevv1e/deck-control-plane` | invites, Windows pairing, пользователи, Spaces, Drive OAuth |
| `keyguard/` | `ghcr.io/stevv1e/deck-keyguard` | устройства, подписи, секреты, egress, лимиты, AI/Git/Drive/media proxy |
| `space-operator/` | `ghcr.io/stevv1e/deck-space-operator` | Kubernetes Spaces, сон, резервные копии и удаление |
| `ssh-gateway/` | `ghcr.io/stevv1e/deck-ssh-gateway` | подписанные SSH-действия и краткоживущие сертификаты |
| `images/keycloak/` | `ghcr.io/stevv1e/deck-keycloak` | Keycloak authenticator, passkey и Windows pairing UI |
| `images/squid/` | `ghcr.io/stevv1e/deck-squid` | базовый образ контролируемого egress |

Android, Windows и `deck-space` backend публикуются из [fugu-deck-app](https://github.com/stevv1e/fugu-deck-app). Официальные модули — [fugu-modules](https://github.com/stevv1e/fugu-modules).

## Документация

- [Архитектура платформы](docs/PLATFORM.md)
- [Полная документация проекта](https://github.com/stevv1e/fugu-deck-app/blob/main/docs/README.md)
- [Техническая архитектура](https://github.com/stevv1e/fugu-deck-app/blob/main/docs/TECHNICAL_ARCHITECTURE.md)
- [Руководство для ИИ-разработчиков](https://github.com/stevv1e/fugu-deck-app/blob/main/docs/AI_DEVELOPMENT_GUIDE.md)
- [Roadmap](https://github.com/stevv1e/fugu-deck-app/blob/main/docs/ROADMAP.md)

## Проверки и сборки

```bash
cd keyguard && go test ./...
cd ../control-plane && go test ./...
cd ../space-operator && go test ./...
cd ../ssh-gateway && go test ./...
```

GitHub Actions:

- `validate` — Go formatting/vet/tests и одноразовый Keycloak integration test;
- `secret-scan` — Gitleaks по исходникам и истории;
- `release` — четыре серверных Go-образа и cosign keyless;
- `platform-images` — Keycloak и Squid с cosign keyless.

Push в main создаёт `main-<sha>`, тег `vX.Y.Z` — `X.Y.Z`. Keycloak/Squid используют platform tags из workflow matrix. Production должен закреплять Keycloak по digest.

## Граница публичного кода

Здесь находятся только generic manifests и примеры. Не коммитьте:

- реальные `kubernetes/clusters/<окружение>`;
- домены/IP/почту владельца и ник администратора;
- invites, pairing secrets, PAT, OAuth secrets, refresh tokens;
- device IDs и списки отзыва конкретной установки;
- приватные ключи, keystores, DB DSN, Terraform state;
- Firebase/VPN/egress credentials.

Лицензия — [Apache-2.0](LICENSE).
