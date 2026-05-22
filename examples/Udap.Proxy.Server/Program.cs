#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityModel;
using Firely.Fhir.Packages;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Hl7.Fhir.Specification.Source;
using Hl7.Fhir.Specification.Terminology;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Serialization;
using Duende.AspNetCore.Authentication.JwtBearer.DPoP;
using Firely.Fhir.Validation;
using Microsoft.AspNetCore.Http.Json;
using Udap.CdsHooks.Model;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Proxy.Server;
using Udap.Proxy.Server.IDIPatientMatch;
using Udap.Metadata.Server.Security;
using Udap.Proxy.Server.Services;
using Udap.Smart.Model;
using Udap.Util.Extensions;
using Yarp.ReverseProxy.Transforms;
using ZiggyCreatures.Caching.Fusion;
using Constants = Udap.Common.Constants;

var builder = WebApplication.CreateBuilder(args);

// Mount Cloud Secrets FIRST - before Serilog reads configuration
builder.Configuration.AddJsonFile("/secret/udapproxyserverappsettings", true, false);
builder.Configuration.AddJsonFile("/secret/metadata/udap.proxy.server.metadata.options.json", true, false);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

builder.Host.UseSerilog();

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
    options.SerializerOptions.Converters.Add(new FhirResourceConverter());
});

builder.Services.Configure<CdsServices>(builder.Configuration.GetRequiredSection("CdsServices"));
builder.Services.Configure<SmartMetadata>(builder.Configuration.GetRequiredSection("SmartMetadata"));
builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection(Constants.UdapFileCertStoreManifestSectionName));

builder.Services.AddCdsServices();
builder.Services.AddSmartMetadata();
builder.Services.AddUdapMetadataServer(builder.Configuration);
builder.Services.AddFusionCache("FhirMetadata")
    .WithDefaultEntryOptions(new FusionCacheEntryOptions
    {
        Duration = TimeSpan.FromMinutes(10),
        FactorySoftTimeout = TimeSpan.FromMilliseconds(100),
        AllowTimedOutFactoryBackgroundCompletion = true,
        FailSafeMaxDuration = TimeSpan.FromHours(12)
    });

builder.Services.AddUdapCertificateCache()
    .WithDefaultEntryOptions(new FusionCacheEntryOptions
    {
        Duration = TimeSpan.FromHours(12),
        FailSafeMaxDuration = TimeSpan.FromHours(48)
    });
builder.Services.AddHttpClient<CertificateDownloadCache>();
builder.Services.AddSingleton<ICertificateDownloadCache, CertificateDownloadCache>();

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// builder.Services.AddAuthentication(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)
builder.Services.AddAuthentication("token")

    // .AddJwtBearer(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, options =>
    .AddJwtBearer("token", OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, options =>
    {
        options.Authority = builder.Configuration["Jwt:Authority"];
        options.RequireHttpsMetadata = bool.Parse(builder.Configuration["Jwt:RequireHttpsMetadata"] ?? "true");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
    });

// layer on dpop validation if a DPoP token is presented
// the authz header will be {dpop accessToken} rather than {bearer accessToken}.
// in addition, a DPoP header must be presented as the proof-of-possession.
builder.Services.ConfigureDPoPTokensForScheme("token", configure =>
{
    // Chose a validation mode: either Nonce or IssuedAt. With nonce validation,
    // the api supplies a nonce that must be used to prove that the token was
    // not pre-generated. With IssuedAt validation, the client includes the
    // current time in the proof token, which is compared to the clock. Nonce
    // validation provides protection against some attacks that are possible
    // with IssuedAt validation, at the cost of an additional HTTP request being
    // required each time the API is invoked.
    //
    // See RFC 9449 for more details.
    configure.ProofTokenExpirationMode = DPoPProofExpirationMode.IssuedAt;
    configure.AllowBearerTokens = true; // Some clients are issued without DPoP capability
});


builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultPolicy", builder =>
    {
        builder.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("udapPolicy", policy =>
        policy.RequireAuthenticatedUser());

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient((_, handler) =>
    {
        // Enable automatic decompression for gzip, deflate, and brotli
        handler.AutomaticDecompression = System.Net.DecompressionMethods.GZip |
                                          System.Net.DecompressionMethods.Deflate |
                                          System.Net.DecompressionMethods.Brotli;
    })
    .AddTransforms(builderContext =>
    {
        // Always forward encoding headers for all routes
        builderContext.AddRequestTransform(context =>
        {
            ForwardEncodingHeaders(context.HttpContext, context.ProxyRequest);
            return ValueTask.CompletedTask;
        });

        builderContext.AddRequestTransform(async context =>
        {
            var accessTokenService = context.HttpContext.RequestServices.GetRequiredService<IAccessTokenService>();
            var accessToken = await accessTokenService.ResolveAccessTokenAsync(
                context.HttpContext.RequestServices.GetRequiredService<ILogger<AccessTokenService>>(),
                cancellationToken: context.HttpContext.RequestAborted);
            context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            SetProxyHeaders(context);
        });

        builderContext.AddResponseTransform(async responseContext =>
        {
            if (responseContext.HttpContext.Request.Path == "/fhir/r4/metadata")
            {
                responseContext.SuppressResponseBody = true;

                // If the backend returned an error, pass through the status and body
                if (responseContext.ProxyResponse != null && !responseContext.ProxyResponse.IsSuccessStatusCode)
                {
                    var errorBytes = await responseContext.ProxyResponse.Content.ReadAsByteArrayAsync();
                    responseContext.HttpContext.Response.StatusCode = (int)responseContext.ProxyResponse.StatusCode;
                    responseContext.HttpContext.Response.ContentLength = errorBytes.Length;
                    await responseContext.HttpContext.Response.Body.WriteAsync(errorBytes);
                    return;
                }

                var cache = responseContext.HttpContext.RequestServices.GetRequiredService<IFusionCacheProvider>().GetCache("FhirMetadata");
                var bytes = await cache.GetOrSetAsync("metadata", _ => GetFhirMetadata(responseContext, builder));

                // Change Content-Length to match the modified body, or remove it.
                responseContext.HttpContext.Response.ContentLength = bytes?.Length;

                // Response headers are copied before transforms are invoked, update any needed headers on the HttpContext.Response.
                await responseContext.HttpContext.Response.Body.WriteAsync(bytes);
            }

            //
            // Rewrite resource URLs
            //
            else if (responseContext.ProxyResponse != null &&
                     responseContext.HttpContext.Request.Path.HasValue &&
                     responseContext.HttpContext.Request.Path.Value.StartsWith("/fhir/r4/", StringComparison.OrdinalIgnoreCase))
            {
                responseContext.SuppressResponseBody = true;
                var stream = await responseContext.ProxyResponse.Content.ReadAsStreamAsync();

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

var disableCompression = Environment.GetEnvironmentVariable("ASPNETCORE_RESPONSE_COMPRESSION_DISSABLED");
if (!string.Equals(disableCompression, "true", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddResponseCompression(options =>
    {
        options.EnableForHttps = true;
        options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat([
            "application/fhir+xml",
            "application/fhir+json"
        ]);
    });
}

builder.Services.AddHttpClient();
builder.Services.AddSingleton<IAccessTokenService, AccessTokenService>();

//
// IDI Patient Match Operations
//
builder.Services.AddSingleton<Validator>(sp =>
{
    IAsyncResourceResolver packageSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/Packages/hl7.fhir.r4b.core-4.3.0.tgz");
    var coreSource = new CachedResolver(packageSource);
    var coreSnapshot = new SnapshotSource(coreSource);
    var terminologySource = new LocalTerminologyService(coreSnapshot);
    IAsyncResourceResolver idiSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/Packages/hl7.fhir.us.identity-matching-2.0.0-ballot.tgz");
    var source = new MultiResolver(idiSource, coreSnapshot);
    var settings = new ValidationSettings { ConformanceResourceResolver = source };
    return new Validator(source, terminologySource, null, settings);

});

builder.Services.AddSingleton<IIdiPatientRules, IdiPatientRules>();
builder.Services.AddSingleton<PatientMatchInValidator>();
builder.Services.AddSingleton<IdiPatientMatchInValidator>();

builder.Services.AddSingleton<IFhirOperation>(sp =>
    new OpMatch(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IAccessTokenService>(),
        sp.GetRequiredService<HttpClient>(),
        sp.GetRequiredService<ILogger<OpMatch>>(),
        sp.GetRequiredService<PatientMatchInValidator>()
    ));

builder.Services.AddSingleton<IFhirOperation>(sp =>
    new OpIdiMatch(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IAccessTokenService>(),
        sp.GetRequiredService<HttpClient>(),
        sp.GetRequiredService<ILogger<OpIdiMatch>>(),
        sp.GetRequiredService<IdiPatientMatchInValidator>()
    ));





var app = builder.Build();

// Force Validator to expand/load packages at startup
using (var scope = app.Services.CreateScope())
{
    var validator = scope.ServiceProvider.GetRequiredService<Validator>();
    var dummyPatient = new Patient { Id = "init" };
    validator.Validate(dummyPatient);
}

// Configure the HTTP request pipeline.
app.UseForwardedHeaders();

// Rewrite community-prefixed paths (e.g., /community-a/fhir/r4/Patient/123)
// to /fhir/r4/Patient/123 so existing YARP routes match.
// Must run before UseRouting() so the correct YARP route is selected.
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value;
    if (path != null)
    {
        var fhirIndex = path.IndexOf("/fhir/r4", StringComparison.OrdinalIgnoreCase);
        if (fhirIndex > 0)
        {
            var communityPrefix = path[..fhirIndex];
            context.Items["OriginalPath"] = path;
            context.Items["CommunityPrefix"] = communityPrefix;
            context.Request.PathBase = context.Request.PathBase.Add(communityPrefix);
            context.Request.Path = path[fhirIndex..];
        }
    }

    await next();
});

// Explicit UseRouting() so the path rewrite above runs before route matching.
app.UseRouting();
app.UseCors("DefaultPolicy");

if (!string.Equals(disableCompression, "true", StringComparison.OrdinalIgnoreCase))
{
    app.UseResponseCompression();
}

app.UseDefaultFiles();
app.UseStaticFiles();

// Write streamlined request completion events, instead of the more verbose ones from the framework.
// To use the default framework request logging instead, remove this line and set the "Microsoft"
// level in appsettings.json to "Information".
app.UseSerilogRequestLogging();

app.UseUdapMetadataServer();

app.UseAuthentication();
app.UseSecurityEventLogging();
app.UseAuthorization();

//
// IDI Patient Match Operations
//
app.UseMiddleware<OperationMiddleware>();


app.UseMiddleware<RouteLoggingMiddleware>();
app.MapReverseProxy();

app.UseCdsServices("fhir/r4");
app.UseSmartMetadata("fhir/r4");

app.Run();


async Task<byte[]?> GetFhirMetadata(ResponseTransformContext responseTransformContext,
    WebApplicationBuilder webApplicationBuilder)
{
    var stream = responseTransformContext.ProxyResponse?.Content != null
        ? await responseTransformContext.ProxyResponse.Content.ReadAsStreamAsync()
        : Stream.Null;

    using var reader = new StreamReader(stream);
    var body = await reader.ReadToEndAsync();

    if (!string.IsNullOrEmpty(body))
    {
        var capStatement = await new FhirJsonParser().ParseAsync<CapabilityStatement>(body);
        var securityComponent = new CapabilityStatement.SecurityComponent();

        securityComponent.Service.Add(
            new CodeableConcept("http://fhir.udap.org/CodeSystem/capability-rest-security-service",
                "UDAP",
                "OAuth2 using UDAP profile (see http://www.udap.org)"));

        //
        // https://build.fhir.org/ig/HL7/fhir-extensions/StructureDefinition-oauth-uris.html
        //
        var oauthUrlExtensions = new Extension();
        var securityExtension = new Extension("http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris", oauthUrlExtensions);
        securityExtension.Extension.Add(new Extension() { Url = "token", Value = new FhirUri(webApplicationBuilder.Configuration["Jwt:Token"]) });
        securityExtension.Extension.Add(new Extension() { Url = "authorize", Value = new FhirUri(webApplicationBuilder.Configuration["Jwt:Authorize"]) });
        securityExtension.Extension.Add(new Extension() { Url = "register", Value = new FhirUri(webApplicationBuilder.Configuration["Jwt:Register"]) });
        securityExtension.Extension.Add(new Extension() { Url = "manage", Value = new FhirUri(webApplicationBuilder.Configuration["Jwt:Manage"]) });
        securityComponent.Extension.Add(securityExtension);
        capStatement.Rest.First().Security = securityComponent;

        body = new FhirJsonSerializer().SerializeToString(capStatement);
        var bytes = Encoding.UTF8.GetBytes(body);
        
        return bytes;
    }

    return null;
}

void SetProxyHeaders(RequestTransformContext requestTransformContext)
{
    var principal = requestTransformContext.HttpContext.User;

    if (principal.Identity is not { IsAuthenticated: true })
    {
        return;
    }

    // Never let the requester set this header.
    requestTransformContext.ProxyRequest.Headers.Remove("X-Authorization-Scope");
    requestTransformContext.ProxyRequest.Headers.Remove("X-Authorization-Issuer");

    var scopes = principal.FindAll("scope");
    var iss = principal.FindFirst("iss");

    // Google Cloud way of passing scopes to the Fhir Server
    var spaceSeparatedString = scopes.Select(s => s.Value)
        .Where(s => s != "udap") //gcp doesn't know udap  Need better filter to block unknown scopes
        .ToSpaceSeparatedString();

    requestTransformContext.ProxyRequest.Headers.Add("X-Authorization-Scope", spaceSeparatedString);
    requestTransformContext.ProxyRequest.Headers.Add("X-Authorization-Issuer", iss?.Value);
}

void ForwardEncodingHeaders(HttpContext httpContext, HttpRequestMessage proxyRequest)
{
    // Forward Accept-Encoding from client to backend
    if (httpContext.Request.Headers.TryGetValue("Accept-Encoding", out var encodings))
    {
        proxyRequest.Headers.Remove("Accept-Encoding");
        proxyRequest.Headers.Add("Accept-Encoding", encodings.ToArray());
    }
    // Forward Content-Encoding if present
    if (httpContext.Request.Headers.TryGetValue("Content-Encoding", out var contentEncodings))
    {
        proxyRequest.Headers.Remove("Content-Encoding");
        proxyRequest.Headers.Add("Content-Encoding", contentEncodings.ToArray());
    }
}