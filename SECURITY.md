# Security Policy

## Reporting a vulnerability

Не публикуйте рабочие exploits, токены или приватные данные установки в GitHub Issues. Откройте приватное сообщение владельцу репозитория через GitHub Security Advisory.

## Publication boundary

Перед merge проверяйте, что изменение не содержит реальных invites, pairing secrets, PAT, OAuth refresh tokens, приватных ключей, DB DSN, device IDs или реальных cluster overlays. Тестовые значения должны быть явно искусственными.

CI запускает Gitleaks по исходникам и истории. Найденный реальный секрет нужно отозвать у провайдера; удаление строки из нового коммита недостаточно.
