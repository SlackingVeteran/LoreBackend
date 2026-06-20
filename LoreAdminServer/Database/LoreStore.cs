// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using LoreBackend.Auth;
using LoreBackend.Server;

namespace LoreBackend.Database
{
    public class LoreStore
    {
        public static readonly string[] AllPerms = new[] { "read", "write", "obliterate", "admin", "migrate" };

        readonly string _connectionString;
        readonly AclEngine _acl;
        readonly LoreOptions _options;

        public LoreStore(IOptions<LoreOptions> options, AclEngine acl)
        {
            _acl = acl;
            _options = options.Value;
            _connectionString = new SqliteConnectionStringBuilder { DataSource = options.Value.DatabasePath }.ToString();
            using SqliteConnection connection = Open();
            Exec(connection, "PRAGMA journal_mode = WAL");
            Exec(connection, @"
CREATE TABLE IF NOT EXISTS orgs (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  org_id        INTEGER REFERENCES orgs(id) ON DELETE SET NULL,
  is_admin      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS repos (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  lore_id TEXT UNIQUE NOT NULL,
  org_id  INTEGER REFERENCES orgs(id) ON DELETE SET NULL,
  slug    TEXT,
  name    TEXT
);
CREATE TABLE IF NOT EXISTS perms (
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  repo_lore_id TEXT NOT NULL,
  perms        TEXT NOT NULL,
  PRIMARY KEY (user_id, repo_lore_id)
);
CREATE TABLE IF NOT EXISTS identities (
  username           TEXT PRIMARY KEY,
  display_name       TEXT,
  preferred_username TEXT,
  claims_json        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name     TEXT NOT NULL,
  key_hash TEXT UNIQUE NOT NULL,
  created  TEXT NOT NULL DEFAULT (datetime('now'))
);");
        }

        SqliteConnection Open()
        {
            SqliteConnection connection = new SqliteConnection(_connectionString);
            connection.Open();
            Exec(connection, "PRAGMA foreign_keys = ON");
            return connection;
        }

        static void Exec(SqliteConnection connection, string sql)
        {
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        static SqliteCommand Cmd(SqliteConnection connection, string sql, params (string, object?)[] args)
        {
            SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            foreach ((string name, object? value) in args)
            {
                command.Parameters.AddWithValue(name, value ?? DBNull.Value);
            }

            return command;
        }

        // ---- password hashing ----
        public static string HashPassword(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
            return Convert.ToHexString(salt).ToLowerInvariant() + ":" + Convert.ToHexString(hash).ToLowerInvariant();
        }

        public static bool VerifyPassword(string password, string stored)
        {
            string[] parts = stored.Split(':');
            if (parts.Length != 2)
            {
                return false;
            }

            byte[] expected = Convert.FromHexString(parts[1]);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromHexString(parts[0]), 100_000, HashAlgorithmName.SHA256, 32);
            return CryptographicOperations.FixedTimeEquals(hash, expected);
        }

        // ---- orgs ----
        public List<Org> ListOrgs()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT id, slug, name FROM orgs ORDER BY slug");
            using SqliteDataReader reader = command.ExecuteReader();
            List<Org> result = new List<Org>();
            while (reader.Read())
            {
                result.Add(new Org(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
            }

            return result;
        }

        public Org? GetOrg(long id)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT id, slug, name FROM orgs WHERE id = $id", ("$id", id));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? new Org(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)) : null;
        }

        public Org? GetOrgBySlug(string slug)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT id, slug, name FROM orgs WHERE slug = $slug", ("$slug", slug));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? new Org(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)) : null;
        }

        public Org CreateOrg(string slug, string? name)
        {
            using SqliteConnection connection = Open();
            using (SqliteCommand command = Cmd(connection, "INSERT INTO orgs (slug, name) VALUES ($slug, $name)", ("$slug", slug), ("$name", string.IsNullOrEmpty(name) ? slug : name)))
            {
                command.ExecuteNonQuery();
            }

            return GetOrgBySlug(slug)!;
        }

        // ---- users ----
        public List<User> ListUsers()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT u.id, u.username, u.password_hash, u.org_id, u.is_admin, o.slug FROM users u LEFT JOIN orgs o ON o.id = u.org_id ORDER BY u.username");
            using SqliteDataReader reader = command.ExecuteReader();
            List<User> result = new List<User>();
            while (reader.Read())
            {
                result.Add(ReadUser(reader));
            }

            return result;
        }

        public User? GetUser(string username)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT u.id, u.username, u.password_hash, u.org_id, u.is_admin, o.slug FROM users u LEFT JOIN orgs o ON o.id = u.org_id WHERE u.username = $u", ("$u", username));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? ReadUser(reader) : null;
        }

        public User CreateUser(string username, string password, long? orgId, bool isAdmin)
        {
            using SqliteConnection connection = Open();
            using (SqliteCommand command = Cmd(connection, "INSERT INTO users (username, password_hash, org_id, is_admin) VALUES ($u, $p, $o, $a)", ("$u", username), ("$p", HashPassword(password)), ("$o", orgId), ("$a", isAdmin ? 1 : 0)))
            {
                command.ExecuteNonQuery();
            }

            return GetUser(username)!;
        }

        public void DeleteUser(long id)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "DELETE FROM users WHERE id = $id", ("$id", id));
            command.ExecuteNonQuery();
        }

        static User ReadUser(SqliteDataReader reader)
        {
            return new User(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetInt64(3),
                reader.GetInt64(4) != 0,
                reader.IsDBNull(5) ? null : reader.GetString(5));
        }

        // ---- repos ----
        public List<Repo> ListRepos()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT r.id, r.lore_id, r.org_id, r.slug, r.name, o.slug FROM repos r LEFT JOIN orgs o ON o.id = r.org_id ORDER BY r.name");
            using SqliteDataReader reader = command.ExecuteReader();
            List<Repo> result = new List<Repo>();
            while (reader.Read())
            {
                result.Add(new Repo(
                    reader.GetInt64(0),
                    reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetInt64(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.IsDBNull(4) ? reader.GetString(1) : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5)));
            }

            return result;
        }

        public void UpsertRepo(string loreId, long? orgId, string? slug, string name)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection,
                "INSERT INTO repos (lore_id, org_id, slug, name) VALUES ($l, $o, $s, $n) ON CONFLICT(lore_id) DO UPDATE SET org_id=excluded.org_id, slug=excluded.slug, name=excluded.name",
                ("$l", loreId), ("$o", orgId), ("$s", slug), ("$n", string.IsNullOrEmpty(name) ? loreId : name));
            command.ExecuteNonQuery();
        }

        public void DeleteRepo(string loreId)
        {
            using SqliteConnection connection = Open();
            using (SqliteCommand command = Cmd(connection, "DELETE FROM perms WHERE repo_lore_id = $l", ("$l", loreId)))
            {
                command.ExecuteNonQuery();
            }

            using (SqliteCommand command = Cmd(connection, "DELETE FROM repos WHERE lore_id = $l", ("$l", loreId)))
            {
                command.ExecuteNonQuery();
            }
        }

        // ---- permissions ----
        public List<Perm> GetPerms(long userId)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT user_id, repo_lore_id, perms FROM perms WHERE user_id = $u", ("$u", userId));
            using SqliteDataReader reader = command.ExecuteReader();
            List<Perm> result = new List<Perm>();
            while (reader.Read())
            {
                result.Add(new Perm(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
            }

            return result;
        }

        public void SetPerm(long userId, string repoLoreId, IEnumerable<string> perms)
        {
            string[] clean = perms.Where(p => AllPerms.Contains(p)).Distinct().ToArray();
            using SqliteConnection connection = Open();
            if (clean.Length == 0)
            {
                using SqliteCommand command = Cmd(connection, "DELETE FROM perms WHERE user_id = $u AND repo_lore_id = $r", ("$u", userId), ("$r", repoLoreId));
                command.ExecuteNonQuery();
            }
            else
            {
                using SqliteCommand command = Cmd(connection,
                    "INSERT INTO perms (user_id, repo_lore_id, perms) VALUES ($u, $r, $p) ON CONFLICT(user_id, repo_lore_id) DO UPDATE SET perms=excluded.perms",
                    ("$u", userId), ("$r", repoLoreId), ("$p", string.Join(",", clean)));
                command.ExecuteNonQuery();
            }
        }

        // ---- OIDC identities ----

        // Ensures an OIDC-authenticated user exists in the users table (for the admin UI and
        // the IsAdmin escape hatch). OIDC users carry no password.
        public User UpsertOidcUser(string username)
        {
            using SqliteConnection connection = Open();
            using (SqliteCommand command = Cmd(connection,
                "INSERT INTO users (username, password_hash, org_id, is_admin) VALUES ($u, '', NULL, 0) ON CONFLICT(username) DO NOTHING",
                ("$u", username)))
            {
                command.ExecuteNonQuery();
            }

            return GetUser(username)!;
        }

        public void UpsertIdentity(string username, string? displayName, string? preferredUsername, IEnumerable<KeyValuePair<string, string>> claims)
        {
            string claimsJson = JsonSerializer.Serialize(claims.Select(c => new[] { c.Key, c.Value }).ToList());
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection,
                "INSERT INTO identities (username, display_name, preferred_username, claims_json) VALUES ($u, $d, $p, $c) ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name, preferred_username=excluded.preferred_username, claims_json=excluded.claims_json",
                ("$u", username), ("$d", displayName), ("$p", preferredUsername), ("$c", claimsJson));
            command.ExecuteNonQuery();
        }

        public OidcIdentity? GetIdentity(string username)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT username, display_name, preferred_username, claims_json FROM identities WHERE username = $u", ("$u", username));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? ReadIdentity(reader) : null;
        }

        public List<OidcIdentity> ListIdentities()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT username, display_name, preferred_username, claims_json FROM identities ORDER BY display_name, username");
            using SqliteDataReader reader = command.ExecuteReader();
            List<OidcIdentity> result = new List<OidcIdentity>();
            while (reader.Read())
            {
                result.Add(ReadIdentity(reader));
            }

            return result;
        }

        static OidcIdentity ReadIdentity(SqliteDataReader reader)
        {
            List<KeyValuePair<string, string>> claims = new List<KeyValuePair<string, string>>();
            string[][]? parsed = JsonSerializer.Deserialize<string[][]>(reader.GetString(3));
            if (parsed != null)
            {
                foreach (string[] pair in parsed)
                {
                    if (pair.Length == 2)
                    {
                        claims.Add(new KeyValuePair<string, string>(pair[0], pair[1]));
                    }
                }
            }

            return new OidcIdentity(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                claims);
        }

        // ---- api keys (non-interactive login) ----
        public string CreateApiKey(long userId, string name)
        {
            string key = "lore_" + Base64Url(RandomNumberGenerator.GetBytes(32));
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "INSERT INTO api_keys (user_id, name, key_hash) VALUES ($u, $n, $h)", ("$u", userId), ("$n", name), ("$h", Sha256Hex(key)));
            command.ExecuteNonQuery();
            return key;
        }

        public List<ApiKey> ListApiKeys()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT a.id, a.user_id, a.name, a.created, u.username FROM api_keys a JOIN users u ON u.id = a.user_id ORDER BY u.username, a.created");
            using SqliteDataReader reader = command.ExecuteReader();
            List<ApiKey> result = new List<ApiKey>();
            while (reader.Read())
            {
                result.Add(new ApiKey(reader.GetInt64(0), reader.GetInt64(1), reader.GetString(2), reader.GetString(3), reader.GetString(4)));
            }

            return result;
        }

        public void DeleteApiKey(long id)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "DELETE FROM api_keys WHERE id = $id", ("$id", id));
            command.ExecuteNonQuery();
        }

        public User? GetUserByApiKey(string rawKey)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT u.id, u.username, u.password_hash, u.org_id, u.is_admin, o.slug FROM users u JOIN api_keys a ON a.user_id = u.id LEFT JOIN orgs o ON o.id = u.org_id WHERE a.key_hash = $h", ("$h", Sha256Hex(rawKey)));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? ReadUser(reader) : null;
        }

        static string Sha256Hex(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
        static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        // Whether a user is an admin. Local users use the DB is_admin flag; OIDC users (those
        // with a stored identity) are admins if their captured claims hold the configured
        // Oidc.AdminClaim (same gate as the dashboard). The DB flag still wins if set.
        public bool IsAdmin(User user)
        {
            if (user.IsAdmin)
            {
                return true;
            }

            OidcIdentity? identity = GetIdentity(user.Username);
            if (identity == null)
            {
                return false;
            }

            AclClaim admin = _options.Oidc.AdminClaim;
            return !string.IsNullOrEmpty(admin.Type) && identity.Claims.Any(c =>
                string.Equals(c.Key, admin.Type, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(c.Value, admin.Value, StringComparison.Ordinal));
        }

        // JWT `resources` claim / permission checks. Resolution order:
        //   admins -> urc-* wildcard; OIDC identities -> ACL rules over their claims;
        //   legacy local users -> their manually-assigned perms.
        public List<ResourceGrant> ResourcesForUser(User user)
        {
            if (user.IsAdmin)
            {
                return new List<ResourceGrant> { new ResourceGrant("urc-*", AllPerms) };
            }

            OidcIdentity? identity = GetIdentity(user.Username);
            if (identity != null)
            {
                return _acl.Resolve(identity.Claims);
            }

            return GetPerms(user.Id).Select(p => new ResourceGrant("urc-" + p.RepoLoreId, p.Perms.Split(',', StringSplitOptions.RemoveEmptyEntries))).ToList();
        }

        // Concrete grants for enumeration (LookupUserPermissions): expand any urc-* wildcard
        // into one grant per known repository, since a wildcard cannot be enumerated.
        public List<ResourceGrant> LookupResourcesForUser(User user)
        {
            List<ResourceGrant> grants = ResourcesForUser(user);
            ResourceGrant? wildcard = grants.FirstOrDefault(g => g.ResourceId == "urc-*");
            if (wildcard == null)
            {
                return grants;
            }

            List<ResourceGrant> expanded = ListRepos().Select(r => new ResourceGrant("urc-" + r.LoreId, wildcard.Permission)).ToList();
            expanded.AddRange(grants.Where(g => g.ResourceId != "urc-*"));
            return expanded;
        }

        public void Seed()
        {
            if (ListUsers().Count == 0)
            {
                Org org = GetOrgBySlug("epic") ?? CreateOrg("epic", "Epic");
                CreateUser("admin", "admin", org.Id, true);
            }
        }
    }
}