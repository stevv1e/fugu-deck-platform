# Squid для deck-egress. Ubuntu 24.04 LTS — та же сборка Squid 6.14, что прошла lab/squid_test.py.
# (Прежний образ ubuntu/squid:6.10-24.10_beta — beta-тег на Ubuntu 24.10, поддержка которой закончилась в 2025.)
# Renovate закрепляет базовый образ по digest; собирает и подписывает .github/workflows/platform-images.yaml.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends squid \
 && rm -rf /var/lib/apt/lists/* \
 && squid -v | head -1
USER 13:13
ENTRYPOINT ["squid"]
CMD ["-N", "-f", "/etc/squid/squid.conf"]
