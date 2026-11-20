# Platform architecture and release boundary

Fugu Deck Platform содержит публичную реализацию серверных компонентов. Приватная установка состоит из этого кода и отдельных deployment-overlays.

## Публичный источник

- Go services со своими unit/integration tests и Dockerfile;
- Keycloak provider/theme и generic realm;
- Squid base image;
- GitHub Actions для тестов, secret scanning, сборки и подписи;
- generic Kubernetes manifests, необходимые для integration tests.

## Приватный источник

- реальные cluster overlays, домены, IP и administrator identity;
- HPKE public key конкретной установки и списки revoked devices;
- OAuth client configuration и внешние egress credentials;
- Terraform tfvars/state и backup credentials.

Секреты не встраиваются в образы. Go services используют distroless multi-stage builds: build stage выполняет tests, final stage получает только статический бинарник. Keycloak получает provider/theme, Squid — только базовую установку.

## Подписи

Серверные Go-образы подписываются identity:

`https://github.com/stevv1e/fugu-deck-platform/.github/workflows/release.yaml@refs/tags/vX.Y.Z`

или `@refs/heads/main` для development builds.

Keycloak/Squid используют `platform-images.yaml` того же репозитория. `deck-space` подписывается отдельным workflow публичного `fugu-deck-app`.

Политика проверки в кластере должна перечислять эти identities. Старые private-monorepo identities можно оставить на переходный период для уже опубликованных digest, затем удалить после переключения всех активных образов.

## Выпуск

1. Все validate/secret-scan jobs должны быть зелёными.
2. Создать тег `vX.Y.Z` для server services.
3. Дождаться release matrix и опубликовать `deck-space` совместимой версии из app.
4. Обновить platform images и закрепить Keycloak digest.
5. Обновить только приватные deployment-overlays.
6. Дождаться Synced/Healthy и выполнить живой OAuth/pairing/model smoke.

Реальные параметры установки никогда не требуются для публичной сборки.
