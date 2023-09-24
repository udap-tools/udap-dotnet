#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using Udap.Client.Authentication;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Client.Rest;
using Udap.Common.Certificates;

using UdapEd.Server.Authentication;
using UdapEd.Server.Extensions;
using UdapEd.Server.Rest;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Host.UseSerilog((ctx, lc) => lc
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
    .MinimumLevel.Override("IdentityModel", LogEventLevel.Debug)
    .MinimumLevel.Override("Duende.Bff", LogEventLevel.Debug)
    .Enrich.FromLogContext()
    .WriteTo.Console(
        outputTemplate:
        "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}",
        theme: AnsiConsoleTheme.Code));

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(60);
    options.Cookie.Name = ".FhirLabs.UdapEd";
    options.Cookie.IsEssential = true;
});

builder.Services.AddControllersWithViews(options =>
{
    // options.Filters.Add(new UserPreferenceFilter());
});

builder.Services.AddRazorPages();
// builder.Services.AddBff();

//
// builder.Services.AddAuthentication(options =>
//     {
//         options.DefaultScheme = "cookie";
//         options.DefaultChallengeScheme = "oidc";
//         options.DefaultSignOutScheme = "oidc";
//     })
//     .AddCookie("cookie", options =>
//     {
//         options.Cookie.Name = "__UdapClientBackend";
//         options.Cookie.SameSite = SameSiteMode.Strict;
//     })
//     .AddOpenIdConnect("oidc", options =>
//     {
//         options.Authority = "https://loclahost:5002";
//
//         // Udap Authorization code flow
//         options.ClientId = "interactive.confidential";  //TODO Dynamic
//         options.ClientSecret = "secret";
//         options.ResponseType = "code";
//         options.ResponseMode = "query";
//
//         options.MapInboundClaims = false;
//         options.GetClaimsFromUserInfoEndpoint = true;
//         options.SaveTokens = true;
//
//         // request scopes + refresh tokens
//         options.Scope.Clear();
//         options.Scope.Add("openid");
//         options.Scope.Add("profile");
//         options.Scope.Add("api");
//         options.Scope.Add("offline_access");
//
//     });

builder.Services.AddScoped<TrustChainValidator>();
builder.Services.AddScoped<UdapClientDiscoveryValidator>();
builder.Services.AddHttpClient<IUdapClient, UdapClient>()
    .AddHttpMessageHandler(sp => new HeaderAugmentationHandler(sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>()));

builder.Services.AddHttpClient(Options.DefaultName, c => { })
    .AddHttpMessageHandler(sp => new HeaderAugmentationHandler(sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>()));

builder.Services.AddScoped<IBaseUrlProvider, BaseUrlProvider>();
builder.Services.AddScoped<IAccessTokenProvider, AccessTokenProvider>();

builder.Services.AddHttpClient<FhirClientWithUrlProvider>((sp, httpClient) =>
{ })
    .AddHttpMessageHandler(sp => new AuthTokenHttpMessageHandler(sp.GetRequiredService<IAccessTokenProvider>()))
    .AddHttpMessageHandler(sp => new HeaderAugmentationHandler(sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>()));

builder.Services.AddHttpContextAccessor();

builder.AddRateLimiting();

// Configure OpenTelemetry
builder.AddOpenTelemetry();

var app = builder.Build();

app.UseSerilogRequestLogging();


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

// app.UseHttpsRedirection();

app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

app.UseRouting();
app.UseRateLimiter(); //after routing

app.UseSession();
app.MapRazorPages();
app.MapControllers()
    .RequireRateLimiting(RateLimitExtensions.Policy)
    ;

app.MapFallbackToFile("index.html");


//
// Created to route traffic through AEGIS Touchstone via a Nginx reverse proxy in my cloud environment.
// Touchstone is also a proxy used to surveil traffic for testing and certification.  
//
if (Environment.GetEnvironmentVariable("proxy-hosts") != null)
{
    var hostMaps = Environment.GetEnvironmentVariable("proxy-hosts")?.Split(";");
    foreach (var hostMap in hostMaps!)
    {
        Log.Information($"Adding host map: {hostMap}");
        File.AppendAllText("/etc/hosts", hostMap + Environment.NewLine);
    }
}

app.Run();
