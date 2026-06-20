// Copyright Lukas Jech 2026. All Rights Reserved.

using System.Collections.Generic;

namespace LoreBackend.Server
{
    public class LoreOptions
    {
        public int GrpcPort { get; set; } = 9443;
        public int HttpPort { get; set; } = 9080;

        public string PublicUrl { get; set; } = "http://localhost:9080";

        public string Issuer { get; set; } = "lore-dev-auth";
        public string KeyId { get; set; } = "lore-dev-key-1";
        public string[] Audiences { get; set; } = new[] { "localhost", "127.0.0.1" };
        public int TokenLifetimeSeconds { get; set; } = 30 * 24 * 60 * 60;

        // Claims stamped into the minted Lore JWT (both required by loreserver's AuthorizationToken).
        // Values can be anything for these 2, they are required but unused by the server
        public string Env { get; set; } = "local";
        public string Idp { get; set; } = "lore-dev";

        public string CertPath { get; set; } = "certs/server.crt";
        public string KeyPath { get; set; } = "certs/server.key";
        public string SigningKeyPath { get; set; } = "certs/jwt-key.b64";
        public string DatabasePath { get; set; } = "lore-admin.db";

        // OIDC identity backend (e.g. Microsoft Entra). When ClientId is empty the service
        // falls back to the local username/password login.
        public OidcOptions Oidc { get; set; } = new OidcOptions();

        // Maps OIDC claims to Lore permissions (Horde-style entries + profiles). Evaluated at
        // login and on every server-side permission check.
        public AclConfig Acl { get; set; } = new AclConfig();
    }

    public class OidcOptions
    {
        // e.g. https://login.microsoftonline.com/<tenant-id>/v2.0
        public string Authority { get; set; } = "";
        public string ClientId { get; set; } = "";
        public string ClientSecret { get; set; } = "";
        public string CallbackPath { get; set; } = "/signin-oidc";
        public List<string> Scopes { get; set; } = new List<string> { "openid", "profile", "email" };

        // Which inbound claim becomes the stable Lore user id, and which is the display name.
        // Defaults are OIDC standard claims (`sub`, `name`), so any compliant IdP works out of
        // the box. On Entra you may prefer `oid` (stable across apps in the tenant) over the
        // per-app `sub` - set UsernameClaim accordingly.
        public string UsernameClaim { get; set; } = "sub";
        public string NameClaim { get; set; } = "name";

        // Claim that grants access to the read-only admin dashboard in OIDC mode (when OIDC is
        // off the dashboard uses Basic auth instead). Defaults to the Lore.Admin role; clear the
        // Type to lock the dashboard entirely.
        public AclClaim AdminClaim { get; set; } = new AclClaim { Type = "roles", Value = "Lore.Admin" };
    }
}