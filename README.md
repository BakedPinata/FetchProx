# FetchProx

FetchProx is a lightweight ASP.NET Core service that fetches HTTP/HTTPS resources on behalf of a client. It is designed to sit behind a VPN and exposes a single `/fetch` endpoint (accessible via GET or POST) that applies basic SSRF protections and size limits.

## Features
- Accepts either POST requests (plain text or JSON bodies) or GET requests with `?url=`/`?u=` query parameters to specify the target URL.
- Blocks access to private, loopback, and link‑local addresses.
- Optional host allowlist to restrict which domains can be fetched.
- Configurable response size limit and timeout.
- Ready to run with Docker or `docker-compose` alongside a VPN container.

## Building and running
```bash
# build the project
 dotnet build

# run locally
 dotnet run --project FetchProx
```
The service listens on port `8080` by default.

## Configuration
Environment variables control runtime behavior:

| Variable | Description | Default |
|----------|-------------|---------|
| `CORS_ORIGINS` | **Required** for cross-origin requests. Comma-separated list of allowed origins (e.g., `https://yourapp.com,https://anotherapp.com`) or `*` for all origins. | *(none - CORS disabled)* |
| `ALLOW_HOSTS` | Comma-separated list of allowed hostnames. Leave blank to allow any public host. | *(none)* |
| `MAX_CONTENT_BYTES` | Maximum size of the upstream response in bytes. | `25000000` |
| `TIMEOUT_SECONDS` | Timeout for requests to the upstream server in seconds. | `30` |
| `RATE_LIMIT_REQUESTS` | Number of requests allowed per time window. | `100` |
| `RATE_LIMIT_WINDOW_MINUTES` | Time window in minutes for rate limiting. | `1` |

### Security Features
- **Rate Limiting**: Configurable request rate limiting to prevent abuse
- **CORS Control**: Explicit CORS origin configuration required for cross-origin requests
- **Enhanced SSRF Protection**: DNS rebinding and time-of-check-time-of-use vulnerability fixes
- **Private IP Filtering**: Blocks access to expanded private IP ranges including carrier NAT and multicast ranges

## Example usage
GET query string:
```bash
curl "http://localhost:8080/fetch?url=https://example.com"
```

POST with plain text:
```bash
curl -X POST http://localhost:8080/fetch \
     -H "Content-Type: text/plain" \
     -d "https://example.com"
```

POST with JSON body:
```bash
curl -X POST http://localhost:8080/fetch \
     -H "Content-Type: application/json" \
     -d '{"url":"https://example.com"}'
```

## Docker
Build and run the container directly:
```bash
docker build -t fetchprox .
docker run -p 8080:8080 fetchprox
```
Or use the provided `docker-compose.yaml` to run alongside the [`gluetun`](https://github.com/qdm12/gluetun) VPN container.

## License
This project is released under the [Apache License 2.0](LICENSE.txt).
