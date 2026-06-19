// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using LoreBackend.Auth;
using LoreBackend.Database;
using LoreBackend.Server;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<LoreOptions>(builder.Configuration.GetSection("Lore"));
builder.Services.PostConfigure<LoreOptions>(options =>
{
    options.SigningKeyPath = Resolve(options.SigningKeyPath);
    options.DatabasePath = Resolve(options.DatabasePath);
});

LoreOptions startupOptions = builder.Configuration.GetSection("Lore").Get<LoreOptions>() ?? new LoreOptions();

builder.Services.AddSingleton<LoreStore>();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton<SessionStore>();
builder.Services.AddGrpc();
builder.Services.AddRazorPages();

builder.WebHost.ConfigureKestrel(kestrel =>
{
    X509Certificate2 certificate = LoadCertificate(startupOptions);
    kestrel.ListenAnyIP(startupOptions.GrpcPort, listen =>
    {
        listen.Protocols = HttpProtocols.Http2;
        listen.UseHttps(certificate);
    });
    kestrel.ListenAnyIP(startupOptions.HttpPort, listen => listen.Protocols = HttpProtocols.Http1);
});

WebApplication app = builder.Build();
app.Services.GetRequiredService<LoreStore>().Seed();
app.UseStaticFiles();
app.MapGrpcService<UrcAuthService>();
app.MapGrpcService<RebacService>();
app.MapRazorPages();
app.MapGet("/jwks.json", (TokenService tokens) => Results.Json(tokens.GetJwks()));
app.Run();

static X509Certificate2 LoadCertificate(LoreOptions options)
{
    using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(Resolve(options.CertPath), Resolve(options.KeyPath));
    return X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
}

static string Resolve(string path)
{
    return Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
}