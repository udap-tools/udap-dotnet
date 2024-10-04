#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Google.Apis.Auth.OAuth2;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using mTLS.Proxy.Server;
using Serilog;
using Serilog.Templates;
using Serilog.Templates.Themes;
using Udap.Util.Extensions;
using Yarp.ReverseProxy.Transforms;
using ZiggyCreatures.Caching.Fusion;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSerilog((services, lc) => lc
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .WriteTo.Console(new ExpressionTemplate(
        // Include trace and span ids when present.
        "[{@t:HH:mm:ss} {@l:u3}{#if @tr is not null} ({substring(@tr,0,4)}:{substring(@sp,0,4)}){#end}] {@m}\n{@x}",
        theme: TemplateTheme.Code)));

// Mount Cloud Secrets
builder.Configuration.AddJsonFile("/secret/mtls_proxy_server_appsettings", true, false);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddFusionCache()
    .WithDefaultEntryOptions(new FusionCacheEntryOptions
    {
        Duration = TimeSpan.FromMinutes(10),
        FactorySoftTimeout = TimeSpan.FromMilliseconds(100),
        AllowTimedOutFactoryBackgroundCompletion = true,
        FailSafeMaxDuration = TimeSpan.FromHours(12)
    });

if (builder.Configuration["BehindLoadBalancer"] == null)
{
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("mTLS_Policy", policy =>
            policy.RequireAuthenticatedUser());
    });

    builder.WebHost.ConfigureKestrel((_, serverOptions) =>
    {
        serverOptions.ConfigureHttpsDefaults(options =>
        {
            options.ServerCertificate = new X509Certificate2(
                builder.Configuration["mTLS_Server_Certificate"]!,
                builder.Configuration["mTLS_Server_Certificate_creds"]);
            options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        });
    });

    builder.Services.AddSingleton<ICertificateValidator, CertificateValidator>();
    builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
        .AddCertificate(options =>
        {
            options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
            options.CustomTrustStore.Clear();
            options.CustomTrustStore.AddRange(new X509Certificate2Collection()
                { new X509Certificate2("SureFhirmTLS_Intermediate.cer"), new X509Certificate2("SureFhirmTLS_CA.cer") });
            options.AllowedCertificateTypes = CertificateTypes.Chained;
            options.RevocationMode = X509RevocationMode.Online;

            options.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = context =>
                {
                    var validationService =
                        context.HttpContext.RequestServices.GetRequiredService<ICertificateValidator>();
                    if (validationService.Validate(context.ClientCertificate))
                    {
                        context.Success();
                    }
                    else
                    {
                        context.Fail("Invalid certificate");
                    }

                    return Task.CompletedTask;
                }
            };
        });
}


builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient((_, handler) =>
    {
        // this is required to decompress automatically.  *******   troubleshooting only   *******
        handler.AutomaticDecompression = System.Net.DecompressionMethods.All;
    })
    .AddTransforms(builderContext =>
    {
        // Conditionally add a transform for routes that require auth.
        if (builderContext.Route.Metadata != null &&
            (builderContext.Route.Metadata.ContainsKey("GCPKeyResolve") || builderContext.Route.Metadata.ContainsKey("AccessToken")))
        {
            builderContext.AddRequestTransform(async context =>
            {
                var resolveAccessToken = await ResolveAccessToken(builderContext.Route.Metadata);
                context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", resolveAccessToken);

                SetProxyHeaders(context);
            });
        }

        // Use the default credentials.  Primary usage: running in Cloud Run under a specific service account
        if (builderContext.Route.Metadata != null && (builderContext.Route.Metadata.TryGetValue("ADC", out string? adc)))
        {
            if (adc.Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                builderContext.AddRequestTransform(async context =>
                {
                    var googleCredentials = GoogleCredential.GetApplicationDefault();
                    string accessToken = await googleCredentials.UnderlyingCredential.GetAccessTokenForRequestAsync();
                    context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                    SetProxyHeaders(context);
                });
            }
        }

        builderContext.AddResponseTransform(async responseContext =>
        {
            //
            // Rewrite resource URLs
            //
            if (responseContext.HttpContext.Request.Path.HasValue &&
                     responseContext.HttpContext.Request.Path.Value.StartsWith("/fhir/r4/", StringComparison.OrdinalIgnoreCase))
            {
                responseContext.SuppressResponseBody = true;
                var stream = await responseContext.ProxyResponse!.Content.ReadAsStreamAsync();

                Console.WriteLine($"RESPONSE CODE: {responseContext.ProxyResponse.StatusCode}");


                using var reader = new StreamReader(stream);
                // TODO: size limits, timeouts
                var body = await reader.ReadToEndAsync();

                var finalBytes = Encoding.UTF8.GetBytes(body.Replace($"\"url\": \"{builder.Configuration["FhirUrlProxy:Back"]}",
                    $"\"url\": \"{builder.Configuration["FhirUrlProxy:Front"]}"));
                responseContext.HttpContext.Response.ContentLength = finalBytes.Length;

                await responseContext.HttpContext.Response.Body.WriteAsync(finalBytes);
            }
        });
    });


// Add services to the container.

var app = builder.Build();

// Configure the HTTP request pipeline.

if (Environment.GetEnvironmentVariable("GCLOUD_PROJECT") != null)
{
    app.Use(async (ctx, next) =>
    {
        var header = ctx.Request.Headers[ForwardedHeadersDefaults.XForwardedProtoHeaderName].FirstOrDefault();
        if (header != null)
        {
            ctx.Request.Scheme = header;
        }

        await next();
    });
}

app.UseDefaultFiles();
app.UseStaticFiles();

// app.UseHttpsRedirection(); // Cannot enabled this when deployed to GCP.  Always an HTTP port 8080 behind load balancer.

// Write streamlined request completion events, instead of the more verbose ones from the framework.
// To use the default framework request logging instead, remove this line and set the "Microsoft"
// level in appsettings.json to "Information".
app.UseSerilogRequestLogging();

app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy();

app.Run();

async Task<string?> ResolveAccessToken(IReadOnlyDictionary<string, string> metadata)
{
    try
    {
        if (metadata.ContainsKey("AccessToken"))
        {
            // You could pass AccessToken as an environment variable
            return builder.Configuration.GetValue<string>(metadata["AccessToken"]);
        }

        var routeAuthorizationPolicy = metadata["GCPKeyResolve"];

        var path = builder.Configuration.GetValue<string>(routeAuthorizationPolicy);

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException(
                $"The route metadata '{routeAuthorizationPolicy}' must be set to a valid path.");
        }

        var credentials = new ServiceAccountCredentialCache();
        return await credentials.GetAccessTokenAsync(path, "https://www.googleapis.com/auth/cloud-healthcare");
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex); //todo: Logger

        return string.Empty;
    }
}

void SetProxyHeaders(RequestTransformContext requestTransformContext)
{
    if (!requestTransformContext.HttpContext.Request.Headers.Authorization.Any())
    {
        return;
    }

    var bearerToken = requestTransformContext.HttpContext.Request.Headers.Authorization.First();

    if (bearerToken == null)
    {
        return;
    }

    foreach (var requestHeader in requestTransformContext.HttpContext.Request.Headers)
    {
        Console.WriteLine(requestHeader.Value);
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var jsonToken = tokenHandler.ReadJwtToken(requestTransformContext.HttpContext.Request.Headers.Authorization.First()?.Replace("Bearer", "").Trim());
    var scopes = jsonToken.Claims.Where(c => c.Type == "scope");
    var iss = jsonToken.Claims.Where(c => c.Type == "iss");
    // var sub = jsonToken.Claims.Where(c => c.Type == "sub"); // figure out what subject should be for GCP


    // Never let the requester set this header.
    requestTransformContext.ProxyRequest.Headers.Remove("X-Authorization-Scope");
    requestTransformContext.ProxyRequest.Headers.Remove("X-Authorization-Issuer");

    // Google Cloud way of passing scopes to the Fhir Server
    var spaceSeparatedString = scopes?.Select(s => s.Value)
        .Where(s => s != "udap") //gcp doesn't know udap  Need better filter to block unknown scopes
        .ToSpaceSeparatedString();

    requestTransformContext.ProxyRequest.Headers.Add("X-Authorization-Scope", spaceSeparatedString);
    requestTransformContext.ProxyRequest.Headers.Add("X-Authorization-Issuer", iss.SingleOrDefault()?.Value);
    // context.ProxyRequest.Headers.Add("X-Authorization-Subject", sub.SingleOrDefault().Value);
}
