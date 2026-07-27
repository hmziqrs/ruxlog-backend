set shell := ["bash", "-euo", "pipefail", "-c"]

api_dir := "backend/api"
api_justfile := "backend/api/justfile"
admin_dir := "frontend/admin-dioxus"
dotenv_bin := "dotenv"

default:
    @just --list

# Docker orchestration ------------------------------------------------------

dev env='dev':
    docker compose --env-file .env.{{env}} --profile services --profile storage up -d
    just storage-init {{env}}

dev-full env='dev':
    docker compose --env-file .env.{{env}} --profile full --profile storage up -d --build
    just storage-init {{env}}

stage:
    just dev-full env=stage

prod:
    just dev-full env=prod

storage-init env='dev':
    scripts/rustfs-bootstrap.sh .env.{{env}}

storage-console env='dev':
    @echo "RustFS Console: http://localhost:$(grep RUSTFS_CONSOLE_PORT .env.{{env}} | cut -d= -f2)"

storage-reset env='dev':
    docker compose --env-file .env.{{env}} stop rustfs
    docker volume rm -f $(grep PROJECT .env.{{env}} | cut -d= -f2)_rustfs_data || true
    just storage-init {{env}}

logs env='dev':
    docker compose --env-file .env.{{env}} logs -f

ps env='dev':
    docker compose --env-file .env.{{env}} ps

down env='dev':
    scripts/compose-down.sh .env.{{env}}

reset env='dev':
    scripts/compose-down.sh .env.{{env}} --volumes

# Database helpers ----------------------------------------------------------

test-db env='test':
    scripts/test-db-setup.sh .env.{{env}}

# Backend API (Axum) --------------------------------------------------------

# Delegate any command to the backend API justfile
api cmd env='dev' *args='':
    {{dotenv_bin}} -e .env.{{env}} -- just -f {{api_justfile}} {{cmd}} {{args}}

api-dev env='dev':
    just dev {{env}}
    {{dotenv_bin}} -e .env.{{env}} -- just -f {{api_justfile}} dev

tui env='dev' *args='':
    cd {{api_dir}} && set -a && source ../../.env.{{env}} && set +a && cargo run --bin ruxlog_tui -- {{args}}

# Frontend (Dioxus) ---------------------------------------------------------

[private]
_fe app cmd env:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="frontend/{{app}}-dioxus"
    case "{{cmd}}" in
        dev)                cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- bash -c 'dx serve --platform web --port ${{uppercase(app)}}_PORT' ;;
        desktop)            cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- bash -c 'dx serve --platform desktop --port ${{uppercase(app)}}_PORT' ;;
        desktop-native)     cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- bash -c 'dx serve --platform desktop --renderer native --port ${{uppercase(app)}}_PORT' ;;
        mobile)             cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- bash -c 'dx serve --platform android --port ${{uppercase(app)}}_PORT' ;;
        mobile-native)      cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- bash -c 'dx serve --platform android --renderer native --port ${{uppercase(app)}}_PORT' ;;
        build)              cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- dx build --platform web --release ;;
        build-desktop)      cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- dx build --platform desktop --release ;;
        build-desktop-native) cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- dx build --platform desktop --renderer native --release ;;
        build-mobile)       cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- dx build --platform android --release ;;
        build-mobile-native) cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- dx build --platform android --renderer native --release ;;
        bundle)             cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- dx bundle --platform web --release ;;
        bundle-desktop)     cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- dx bundle --platform desktop --release ;;
        bundle-mobile)      cd "$dir" && {{dotenv_bin}} -e "../../.env.{{env}}" -- dx bundle --platform android --release ;;
        tailwind)           cd "$dir" && bun run tailwind ;;
        tailwind-build)     cd "$dir" && bun run tailwind:build ;;
        install)            {{dotenv_bin}} -e ".env.{{env}}" -- bash -lc "cd '$dir' && bun install" ;;
        clean)              {{dotenv_bin}} -e ".env.{{env}}" -- bash -lc "cd '$dir' && cargo clean" ;;
        *)                  echo "Unknown frontend command: {{cmd}}" && exit 1 ;;
    esac

# Admin frontend
admin cmd='dev' env='dev':
    just _fe admin {{cmd}} {{env}}

# Consumer frontend
consumer cmd='dev' env='dev':
    just _fe consumer {{cmd}} {{env}}

# Desktop builds (with and without native renderer)
admin-desktop env='dev':
    just _fe admin desktop {{env}}

admin-desktop-native env='dev':
    just _fe admin desktop-native {{env}}

consumer-desktop env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- bash -lc 'dx serve --platform desktop --no-default-features --features "desktop basic" --port ${CONSUMER_PORT}'

consumer-desktop-native env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- bash -lc 'dx serve --platform desktop --renderer native --no-default-features --features "desktop basic" --port ${CONSUMER_PORT}'

# Mobile builds (Android only - with and without native renderer)
admin-mobile env='dev':
    just _fe admin mobile {{env}}

admin-mobile-native env='dev':
    just _fe admin mobile-native {{env}}

consumer-mobile env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- bash -lc 'dx serve --platform android --no-default-features --features "mobile basic" --port ${CONSUMER_PORT}'

consumer-mobile-native env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- bash -lc 'dx serve --platform android --renderer native --no-default-features --features "mobile basic" --port ${CONSUMER_PORT}'

# Production builds for desktop and mobile
admin-build-desktop env='dev':
    just _fe admin build-desktop {{env}}

admin-build-desktop-native env='dev':
    just _fe admin build-desktop-native {{env}}

admin-build-mobile env='dev':
    just _fe admin build-mobile {{env}}

admin-build-mobile-native env='dev':
    just _fe admin build-mobile-native {{env}}

consumer-build-desktop env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- dx build --platform desktop --release --no-default-features --features "desktop basic"

consumer-build-desktop-native env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- dx build --platform desktop --renderer native --release --no-default-features --features "desktop basic"

consumer-build-mobile env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- dx build --platform android --release --no-default-features --features "mobile basic"

consumer-build-mobile-native env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- dx build --platform android --renderer native --release --no-default-features --features "mobile basic"

# Bundling for distribution
admin-bundle-desktop env='dev':
    just _fe admin bundle-desktop {{env}}

admin-bundle-mobile env='dev':
    just _fe admin bundle-mobile {{env}}

consumer-bundle-desktop env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- dx bundle --platform desktop --release --no-default-features --features "desktop basic"

consumer-bundle-mobile env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    env_name="{{env}}"
    env_name="${env_name#env=}"
    cd frontend/consumer-dioxus
    {{dotenv_bin}} -e "../../.env.${env_name}" -- dx bundle --platform android --release --no-default-features --features "mobile basic"

# Admin-specific recipes -----------------------------------------------------

admin-editor-build env='dev':
    {{dotenv_bin}} -e .env.{{env}} -- bash -lc 'cd {{admin_dir}} && bun run editor:build'

admin-editor-watch env='dev':
    {{dotenv_bin}} -e .env.{{env}} -- bash -lc 'cd {{admin_dir}} && bun run editor:watch'

admin-rpxy env='dev':
    {{dotenv_bin}} -e .env.{{env}} -- bash -lc 'cd {{admin_dir}} && bun run rpxy'

# Production GHCR-image stack (backend/docker/docker-compose.prod.yml) --------
# These wrap the production compose that runs the PUBLISHED image plus Postgres,
# Valkey, and Watchtower. Bring the Traefik edge proxy up first and prepare
# backend/docker/deploy.env (copy from deploy.env.example). See
# backend/api/docs/DEPLOY_STEPS.md. (Distinct from the local `prod` recipe
# above, which builds the dev-full stack from source.)

prod_compose := "backend/docker/docker-compose.prod.yml"
prod_envfile := "backend/docker/deploy.env"

# Bring the prod stack up (pulls ${BACKEND_IMAGE}).
deploy:
    docker compose --env-file {{prod_envfile}} -f {{prod_compose}} up -d

deploy-build:
    docker compose --env-file {{prod_envfile}} -f {{prod_compose}} up -d --build

deploy-down:
    docker compose --env-file {{prod_envfile}} -f {{prod_compose}} down

deploy-logs:
    docker compose --env-file {{prod_envfile}} -f {{prod_compose}} logs -f

deploy-ps:
    docker compose --env-file {{prod_envfile}} -f {{prod_compose}} ps

# Run sea-orm migrations as a one-shot against the prod stack. Requires the
# `migrate` binary to be present in the image (see DEPLOY_STEPS.md §3 for the
# interim host-based `cargo run -p migration --bin migrate -- up` path until
# Dockerfile.api is extended to copy /app/migrate).
deploy-migrate *args='up':
    docker compose --env-file {{prod_envfile}} -f {{prod_compose}} run --rm backend /app/migrate {{args}}

# End-to-end (issue #33) -----------------------------------------------------
# Brings the API up locally, then runs the Rust integration suite + bash smoke
# scripts against it (mirrors `.github/workflows/e2e.yml`).
#
# Prereqs: `just dev {{env}}` (or otherwise) has Postgres + Valkey reachable per
# .env.{{env}}, and POSTGRES_HOST/PORT in that env are reachable FROM THE HOST
# (not a docker-internal alias). Valkey must be started with `--requirepass` and
# matching REDIS_USER/REDIS_PASSWORD because the API's fred pool always AUTHs.
e2e env='dev':
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{api_dir}}
    set -a; source "../../.env.{{env}}"; set +a
    export HOST="${HOST:-127.0.0.1}"
    export PORT="${PORT:-8888}"
    export BASE_URL="http://${HOST}:${PORT}"
    echo "BASE_URL=${BASE_URL}"
    cargo run -p migration --bin migrate -- up
    SEED_TEST_USER=1 cargo test --test seed_test_user --features full -- --nocapture --exact seed_test_user
    cargo run --bin ruxlog --features full > /tmp/ruxlog-e2e.log 2>&1 &
    SERVER_PID=$!
    trap '
      kill ${SERVER_PID} 2>/dev/null || true
      pkill -f "target/debug/ruxlog" 2>/dev/null || true
      wait ${SERVER_PID} 2>/dev/null || true
      echo "----- server log (tail 100) -----"; tail -n 100 /tmp/ruxlog-e2e.log || true
    ' EXIT
    echo "Waiting for ${BASE_URL}/healthz ..."
    ok=0
    for i in $(seq 1 240); do
      code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/healthz" || echo 000)
      if [ "${code}" = "200" ]; then ok=1; break; fi
      sleep 1
    done
    if [ "${ok}" != "1" ]; then echo "::error::API did not become healthy"; exit 1; fi
    cargo test --features full --test api_integration
    bash tests/post_v1_smoke.sh
    bash tests/tag_v1_sort_smoke.sh
    bash tests/comment_moderation_v1_smoke.sh
    bash tests/auth_v1_smoke.sh
    echo "===== e2e PASSED ====="

