# Keycloak с модулем deck-invite (первый вход по приглашению без почты; provider/README в исходниках).
# Собирает и подписывает .github/workflows/platform-images.yaml. Версия Keycloak — та же, что в provider/pom.xml.
FROM maven:3.9-eclipse-temurin-21 AS provider
WORKDIR /src
COPY provider/pom.xml .
RUN mvn -q -B dependency:resolve dependency:resolve-plugins
COPY provider/src ./src
RUN mvn -q -B package

FROM quay.io/keycloak/keycloak:26.7.5 AS build
COPY --from=provider /src/target/deck-invite.jar /opt/keycloak/providers/
COPY theme/fugu /opt/keycloak/themes/fugu
# Параметры времени сборки — те же, что задаёт оператор (kubernetes/platform/keycloak/keycloak.yaml): с ними
# образ стартует без пересборки на корневой ФС только для чтения.
# Список должен совпадать с параметрами оператора ЦЕЛИКОМ: при расхождении хотя бы в одном Keycloak, запущенный
# с --optimized, завершается с кодом 2 сразу после строки «build time options ... differ» (так упал первый запуск:
# не хватало spi-x509cert-lookup--provider). test.sh проверяет это запуском образа с параметрами оператора.
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_METRICS_ENABLED=true \
    KC_FEATURES=dpop,passkeys \
    KC_FEATURES_DISABLED=token-exchange-standard,device-flow,impersonation,ciba,kerberos \
    KC_SPI_X509CERT_LOOKUP__PROVIDER=traefik
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.7.5
COPY --from=build /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
