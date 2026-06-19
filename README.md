# LoreAdminServer

Proof-of-concept authentication and authorization service for the Lore VCS. It implements the two gRPC
services the lore server calls into (`epic_urc.UrcAuthApi`, `ucs.auth.RebacApi`), mints per-user JWTs,
and serves a small admin UI for organizations, users, repositories and permissions.

## Settings

Set under the `Lore` section of `appsettings.json` (defaults shown):

* `PublicUrl` (`http://localhost:9080`): external origin of the browser login page. Set this to your
  public URL when running behind a reverse proxy.
* `GrpcPort` (`9443`): TLS gRPC endpoint that the lore server and CLI connect to.
* `HttpPort` (`9080`): HTTP endpoint serving `/jwks.json`, `/login` and `/admin`.
* `Audiences` (`["localhost", "127.0.0.1"]`): JWT audiences; must include the host clients use to reach
  the lore remote.
* `CertPath` / `KeyPath` (`certs/server.crt`, `certs/server.key`): TLS certificate for the gRPC endpoint.

Admin UI default login: `admin` / `admin`.

## Config to give the lore server

In the lore server's config (for example `loreconfig/local.toml`):

```toml
[environment.endpoint]
auth_url = "https://localhost:9443"

[server.auth]
jwt_audience = ["localhost", "127.0.0.1"]

[server.auth.jwk]
endpoint = "http://127.0.0.1:9080/jwks.json"
```

## Run

```bash
dotnet run --project LoreAdminServer     # this service
loreserver --config loreconfig           # the lore server, in its own terminal
```
