// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using LoreBackend.Database;
using LoreBackend.Server;

namespace LoreBackend.Auth
{
    public class TokenService
    {
        readonly LoreOptions _options;
        readonly LoreStore _store;
        readonly RSA _rsa;
        readonly RsaSecurityKey _key;
        readonly JsonWebTokenHandler _handler = new JsonWebTokenHandler();

        public TokenService(IOptions<LoreOptions> options, LoreStore store)
        {
            _options = options.Value;
            _store = store;

            _rsa = RSA.Create(2048);
            if (File.Exists(_options.SigningKeyPath))
            {
                _rsa.ImportRSAPrivateKey(Convert.FromBase64String(File.ReadAllText(_options.SigningKeyPath)), out _);
            }
            else
            {
                File.WriteAllText(_options.SigningKeyPath, Convert.ToBase64String(_rsa.ExportRSAPrivateKey()));
            }

            _key = new RsaSecurityKey(_rsa) { KeyId = _options.KeyId };
        }

        public string MintToken(User user)
        {
            List<object> resources = new List<object>();
            foreach (ResourceGrant grant in _store.ResourcesForUser(user))
            {
                resources.Add(new { resource_id = grant.ResourceId, permission = grant.Permission });
            }

            // Prefer the display name / preferred_username captured from the IdP, falling back
            // to the bare username for legacy local accounts.
            OidcIdentity? identity = _store.GetIdentity(user.Username);
            string name = identity?.DisplayName ?? user.Username;
            string preferredUsername = identity?.PreferredUsername ?? user.Username;

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Issuer = _options.Issuer,
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddSeconds(_options.TokenLifetimeSeconds),
                SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.RsaSha256),
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = user.Username,
                    ["name"] = name,
                    ["preferred_username"] = preferredUsername,
                    ["env"] = _options.Env,
                    ["idp"] = _options.Idp,
                    ["aud"] = JsonSerializer.SerializeToElement(_options.Audiences),
                    ["resources"] = JsonSerializer.SerializeToElement(resources),
                },
            };
            return _handler.CreateToken(descriptor);
        }

        public async Task<User?> AuthenticateAsync(string? authorizationHeader)
        {
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return null;
            }

            string token = authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? authorizationHeader.Substring(7) : authorizationHeader;
            string? sub = await ValidateAsync(token);
            return sub == null ? null : _store.GetUser(sub);
        }

        public async Task<string?> ValidateAsync(string token)
        {
            TokenValidationParameters parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _options.Issuer,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _key,
            };
            TokenValidationResult result = await _handler.ValidateTokenAsync(token, parameters);
            if (!result.IsValid)
            {
                return null;
            }

            return ((JsonWebToken)result.SecurityToken).GetClaim("sub").Value;
        }

        public object GetJwks()
        {
            RSAParameters parameters = _rsa.ExportParameters(false);
            return new
            {
                keys = new object[]
                {
                    new
                    {
                        kty = "RSA",
                        alg = "RS256",
                        kid = _options.KeyId,
                        use = "sig",
                        n = Base64UrlEncoder.Encode(parameters.Modulus),
                        e = Base64UrlEncoder.Encode(parameters.Exponent),
                    },
                },
            };
        }
    }
}