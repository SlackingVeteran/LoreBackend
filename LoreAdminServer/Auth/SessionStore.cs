// Copyright Lukas Jech 2026. All Rights Reserved.

using System.Collections.Concurrent;

namespace LoreBackend.Auth
{
    public class SessionStore
    {
        public class Session
        {
            public bool Authorized { get; set; }
            public string? Username { get; set; }
        }

        readonly ConcurrentDictionary<string, Session> _sessions = new ConcurrentDictionary<string, Session>();

        public void Create(string code)
        {
            _sessions[code] = new Session();
        }

        public Session? Get(string code)
        {
            return _sessions.TryGetValue(code, out Session? session) ? session : null;
        }

        public void Authorize(string code, string username)
        {
            Session session = _sessions.GetOrAdd(code, _ => new Session());
            session.Authorized = true;
            session.Username = username;
        }
    }
}