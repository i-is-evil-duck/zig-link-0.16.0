# zig-link

A minimal link shortener written in Zig (0.16), built as a single static-ish
binary served by a hand-rolled HTTP/1.1 server. Base for this project:
[j3lybin.0.16.0](https://github.com/i-is-evil-duck/j3lybin.0.16.0).

## Features

- 6-character alphanumeric short links (`https://host/abcdef`)
- Case-insensitive: `AbCdEf`, `ABCDEF`, and `abcdef` resolve to the same link
- Server-side ID generation with collision retry
- Expiring links (TTL dropdown on the page; default 48h, max 6 months)
- 302 redirects (temporary, so links stay trackable/correctable)
- Web page plus JSON API for scripts
- Per-IP rate limit (100 links / hour)
- HTTP keep-alive with a 60s idle timeout
- Data persists in `<id>.json` files under `/app/data`
- Cleanup thread removes expired links every 60s

## Quick start

```sh
docker compose up -d --build
```

Visit `http://localhost:8081`. Change the host port in `docker-compose.yml`
(`ports: "8081:8080"`) as needed.

## API

Create a link:

```sh
curl -d '{"url":"https://example.com","ttl":"48h"}' -H 'Content-Type: application/json' http://localhost:8081/api
```

Response:

```json
{"id":"abc123","short":"http://localhost:8081/abc123","url":"https://example.com","ttl_seconds":172800}
```

Form-encoded also works:

```sh
curl -d 'url=https%3A%2F%2Fexample.com&ttl=48h' http://localhost:8081/api
```

Errors: `400` invalid/missing URL, `413` body too large, `429` rate limit,
`500` id allocation failure.

## Routes

| Path             | Description                                   |
| ---------------- | --------------------------------------------- |
| `/`              | Web page                                      |
| `/api` (POST)    | Create a short link (JSON or form-encoded)    |
| `/<id>` (GET)    | 302 redirect to the target URL                |

## Storage

Links live as JSON files in the volume-mounted `data/` directory:

```json
{ "url": "https://example.com", "created_at": 1752000000, "ttl_seconds": 172800 }
```

Redirects read the file directly (no in-memory cache); TTL is enforced both per
request and by the background cleanup thread.

## URLs validation

Only `http://` and `https://` URLs are shortened. Control characters,
whitespace, quotes, and backslashes are rejected, which keeps the JSON store
and the `Location` header safe from injection. The server never fetches the
target URL, so there's no SSRF surface.

## Development

Requires the bundled toolchain tarball `zig-x86_64-linux-0.16.0.tar.xz` at the
repo root; the Dockerfile extracts it during the build stage.

```sh
zig build -Doptimize=ReleaseFast
./zig-out/bin/zig-link 8080
```