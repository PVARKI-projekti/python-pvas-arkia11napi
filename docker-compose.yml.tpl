version: '3.7'

# DB config
x-dbconfig_env: &dbconfig_env
  DB_HOST: db
  DB_USER: &dbuser postgres
  DB_DATABASE: &dbname pvarki
  DB_PASSWORD: &dbpass {{.Env.DB_PASSWORD}} # pragma: allowlist secret
  DB_PORT: &dbport 5432


# Mailer config (don't ask about some of the key names)
x-mailconfig_env: &mailconfig_env
  MAIL_FROM: "{{getenv "MAIL_FROM" "noreply@pvarki.fi"}}"
  #SUPPRESS_SEND: 1 # If you need to suppress for a moment
  MAIL_USERNAME: "{{.Env.MAIL_USERNAME}}" # MUST be set even if not used
  MAIL_PASSWORD: "{{.Env.MAIL_PASSWORD}}" # MUST be set even if not used
  USE_CREDENTIALS: "1" # Set to 1 if you need user/pass for the server
  MAIL_PORT: {{.Env.MAIL_PORT}}
  MAIL_SERVER: {{.Env.MAIL_SERVER}}
  MAIL_STARTTLS: "{{.Env.MAIL_STARTTLS}}" # Try to upgrade to TLS
  MAIL_SSL_TLS: "{{.Env.MAIL_SSL_TLS}}" # Force TLS

# JWT keys, for testing we default to the test keys, should be specified as secrets though
x-jwtconfig_env: &jwtconfig_env
  JWT_PRIVKEY_PATH: "{{.Env.JWT_PRIVKEY_PATH}}"
  JWT_PUBKEY_PATH: "{{.Env.JWT_PUBKEY_PATH}}"
  JWT_PRIVKEY_PASS: "{{.Env.JWT_PRIVKEY_PASS}}" # pragma: allowlist secret
  JWT_COOKIE_SECURE: "1"
  JWT_COOKIE_DOMAIN: "pvarki.fi"


services:
  db:
    image: postgres:15.1
    environment:
      POSTGRES_USER: *dbuser
      POSTGRES_DB: *dbname
      POSTGRES_PASSWORD: *dbpass # pragma: allowlist secret
      LC_COLLATE: "C.UTF-8"
    ports:
      - target: 5432
        published: *dbport
        protocol: tcp
        mode: host
    networks:
      - dbnet
    healthcheck:
      test: "pg_isready --dbname=$$POSTGRES_DB --username=$$POSTGRES_USER -q"
      interval: 5s
      timeout: 5s
      retries: 3
      start_period: 5s
    volumes:
      - 'db_data:/var/lib/postgresql/data'

  dbinit:
    image: pvarkiprojekti/arkia11nmodels:latest
    environment:
      <<: *dbconfig_env
    networks:
      - dbnet
    depends_on:
      db:
        condition: service_healthy

  api:
    image: pvarkiprojekti/arkia11napi:latest
    build:
      context: .
      dockerfile: Dockerfile
      target: production
    environment:
      <<: *dbconfig_env
      <<: *mailconfig_env
      <<: *jwtconfig_env
    depends_on:
      db:
        condition: service_healthy
      dbinit:
        condition: service_completed_successfully
    networks:
      - dbnet
    expose:
      - 8000
    ports:
      - "8000:8000"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.fastapi.rule=Host(`{{.Env.SERVER_ADDRESS}}`)"
      - "traefik.http.routers.fastapi.tls=true"
      - "traefik.http.routers.fastapi.tls.certresolver=letsencrypt"

  traefik:
    image: traefik:v2.2
    networks:
      - dbnet
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "$PWD/traefik.toml:/etc/traefik/traefik.toml"

networks:
  dbnet:

volumes:
  db_data:
    driver: local
