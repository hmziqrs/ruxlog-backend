# Production Deployment Steps

This guide brings up the full production stack: the backend API image from GHCR,
Postgres, Valkey, and Watchtower for zero-SSH auto-updates. The Traefik edge
proxy is a separate compose project that owns the shared external network and
TLS termination.

> Files for issue #48 (GHCR publish + prod compose + Watchtower):
> - `backend/docker/docker-compose.prod.yml` — the full app stack
> - `backend/docker/deploy.env.example` — copy to `deploy.env` and fill in
> - `.github/workflows/publish-image.yml` — builds/pushes the image on `v*` tags
> - `backend/api/docs/DEPLOY_STEPS.md` + `WATCHTOWER_SETUP.md` — this guide

## 0. Prerequisites on the VPS

- Docker + Docker Compose plugin (`docker compose version`).
- A non-root user with access to the Docker daemon.
- The repo checked out at `/opt/ruxlog` (or similar) — the prod compose and
  `deploy.env` are read from disk; secrets never live in CI.

## 1. Backend environment

```bash
cd /opt/ruxlog/backend/docker
cp deploy.env.example deploy.env
# Edit deploy.env: set PROJECT, BACKEND_IMAGE, BACKEND_DOMAIN, ACME_EMAIL, and
# real DB/Redis/SMTP/S3/FCM credentials. HOST/PORT are forced by compose and
# must NOT be set here.
```

`deploy.env` is used two ways at once: (a) compose interpolation for `${VAR}`
references in `docker-compose.prod.yml`, and (b) the backend container's
runtime env (the service lists it under `env_file`). So every stack command
must pass `--env-file deploy.env`.

## 2. Traefik edge proxy (bring up first)

The Traefik stack creates the `${PROJECT}_network` that the app stack joins as
external, and terminates TLS using the file-provider router/middlewares defined
in `backend/traefik/dynamic/traefik-dynamic.yml`. Do NOT redefine them in the
app stack — it reuses `secure-transport-headers@file` / `spa-csp-headers@file`
and routes via the `api-spa-secure` router whose `api-backend` load-balancer
target is `http://api:8888`.

```bash
cd /opt/ruxlog/backend/traefik
cp .env.prod.example .env.prod      # set ACME_EMAIL
mkdir -p data && touch data/acme.json && chmod 600 data/acme.json
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d
```

## 3. Database migrations

The prod image (`backend/docker/Dockerfile.api`) ships only the `ruxlog` API
binary — it has no embedded migrator and no `migrate` subcommand. The
sea-orm-migration CLI lives in the `migration` crate (binary `migrate`,
`backend/api/migration/src/main.rs`).

**Recommended (interim, no image change):** build the migrator on the host from
the repo checkout and run it against the prod database. From the host (outside
the compose network) use the host-side address of Postgres — e.g. publish the
port or point at the VPS private IP:

```bash
cd /opt/ruxlog/backend/api
DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@<postgres-host>:5432/${POSTGRES_DB}" \
  cargo run -p migration --bin migrate -- up
```

Sanity-check connectivity first:

```bash
docker exec -i ${PROJECT}_postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c "SELECT 1"
```

**Follow-up (cleaner):** extend `Dockerfile.api` to also copy the `migrate`
binary (`COPY --from=builder /workspace/api/target/release/migrate /app/migrate`),
then run it as a one-shot against the live stack:

```bash
docker compose --env-file deploy.env -f backend/docker/docker-compose.prod.yml \
  run --rm backend /app/migrate up
```

The sea-orm CLI accepts `up`, `down`, `fresh`, `status`. Run `up` before
starting a newly versioned backend for the first time, and after pulling any
image whose release notes mention a schema change.

## 4. Bring up the application stack

```bash
cd /opt/ruxlog
docker compose --env-file backend/docker/deploy.env \
  -f backend/docker/docker-compose.prod.yml up -d
```

Verify:

```bash
docker compose --env-file backend/docker/deploy.env \
  -f backend/docker/docker-compose.prod.yml ps
curl -I https://api.example.com/healthz     # through Traefik
docker logs ${PROJECT}_backend
```

## 5. CI/CD with GitHub Actions

The workflow at `.github/workflows/publish-image.yml` builds and pushes the
image to GHCR. On push of a version tag (e.g. `v1.2.3`):

1. Build & push image with tags:
   - `ghcr.io/<owner>/<repo>:v1.2.3` (full tag)
   - `ghcr.io/<owner>/<repo>:1.2.3` (raw semver)
   - `ghcr.io/<owner>/<repo>:latest` (only for stable `x.y.z`)
2. The VPS auto-detects and rolls out via Watchtower polling (no SSH, no
   webhooks). See `WATCHTOWER_SETUP.md`.

Build context is `./backend` and the Dockerfile is `backend/docker/Dockerfile.api`
(the correct paths; the old misplaced `backend/api/.github/workflows/cicd.yml`
used `context: .` + `file: Dockerfile` from the wrong directory and has been
removed). Feature flags are NOT overridden by the workflow — the image is built
exactly as `Dockerfile.api` decides.

**Secrets:** none beyond the automatically-provided `GITHUB_TOKEN`
(`packages: write`). Images publish to a GHCR package; if it is private, run
`docker login ghcr.io` on the VPS with a PAT that has `read:packages`.

**Manual run:** from the Actions tab use "Run workflow" and set `version` to a
tag (e.g. `v1.2.3`) to rebuild/redeploy that exact version.

**Pre-releases:** tags that don't match strict `x.y.z` (e.g. `v1.2.3-rc.1`)
publish `v1.2.3-rc.1` + `1.2.3-rc.1` but do NOT move `latest`.

**Rollback:** pin `BACKEND_IMAGE` to a prior tag and bounce the backend (run
`... migrate down` or restore from backup first if the rollback crosses a
migration):

```bash
BACKEND_IMAGE=ghcr.io/<owner>/<repo>:v1.2.2 \
  docker compose --env-file backend/docker/deploy.env \
  -f backend/docker/docker-compose.prod.yml up -d backend
```

## Optional: Local Label-Based Routing

```bash
docker compose --env-file backend/docker/deploy.env \
  -f backend/traefik/docker-compose.dev.yml up -d
# Traefik now serves backend.localhost → backend container
```
