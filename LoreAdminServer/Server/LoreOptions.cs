// Copyright Lukas Jech 2026. All Rights Reserved.

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

        public string CertPath { get; set; } = "certs/server.crt";
        public string KeyPath { get; set; } = "certs/server.key";
        public string SigningKeyPath { get; set; } = "certs/jwt-key.b64";
        public string DatabasePath { get; set; } = "lore-admin.db";
    }
}