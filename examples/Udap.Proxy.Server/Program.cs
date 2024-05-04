using IdentityModel;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Udap.Proxy.Server;
using Yarp.ReverseProxy.Transforms;
using Google.Apis.Auth.OAuth2;
using Udap.Smart.Model;
using Hl7.Fhir.Rest;
using Hl7.Fhir.Serialization;
using Hl7.Fhir.Model;
using System;
using Microsoft.IdentityModel.JsonWebTokens;
using ZiggyCreatures.Caching.Fusion;
using Task = System.Threading.Tasks.Task;
using System.IdentityModel.Tokens.Jwt;
using Udap.Util.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Mount Cloud Secrets
builder.Configuration.AddJsonFile("/secret/udapproxyserverappsettings", true, false);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.Configure<SmartMetadata>(builder.Configuration.GetRequiredSection("SmartMetadata"));
builder.Services.AddSmartMetadata();
builder.Services.AddUdapMetadataServer(builder.Configuration);
builder.Services.AddFusionCache()
    .WithDefaultEntryOptions(new FusionCacheEntryOptions
    {
        Duration = TimeSpan.FromMinutes(10),
        FactorySoftTimeout = TimeSpan.FromMilliseconds(100),
        AllowTimedOutFactoryBackgroundCompletion = true,
        FailSafeMaxDuration = TimeSpan.FromHours(12)
    });

builder.Services.AddAuthentication(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)

    .AddJwtBearer(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, options =>
    {
        options.Authority = builder.Configuration["Jwt:Authority"];
        options.RequireHttpsMetadata = bool.Parse(builder.Configuration["Jwt:RequireHttpsMetadata"] ?? "true");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("udapPolicy", policy =>
        policy.RequireAuthenticatedUser());
});


builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient((context, handler) =>
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
                

                var tokenHandler = new JwtSecurityTokenHandler();
                var jsonToken = tokenHandler.ReadJwtToken(context.HttpContext.Request.Headers.Authorization.ToString().Replace("Bearer", "").Trim());
                var scopes = jsonToken?.Claims.Where(c => c.Type == "scope");
                var iss = jsonToken.Claims.Where(c => c.Type == "iss");
                // var sub = jsonToken.Claims.Where(c => c.Type == "sub"); // figure out what subject should be for GCP

                // Google Cloud way of passing scopes to the Fhir Server
                var spaceSeparatedString = scopes?.Select(s => s.Value)
                    .Where(s => s != "udap") //gcp doesn't know udap  Need better filter to block unknown scopes
                    .ToSpaceSeparatedString();
                //logger
                Console.WriteLine(spaceSeparatedString);

                context.ProxyRequest.Headers.Add("X-Authorization-Scope", spaceSeparatedString);
                context.ProxyRequest.Headers.Add("X-Authorization-Issuer", iss.SingleOrDefault().Value);
                // context.ProxyRequest.Headers.Add("X-Authorization-Subject", sub.SingleOrDefault().Value);
            });
        }

        // Use the default credentials.  Primary usage: running in Cloud Run under a specific service account
        if (builderContext.Route.Metadata != null && (builderContext.Route.Metadata.TryGetValue("ADC", out string? adc)))
        {
            if (adc == "True")
            {
                builderContext.AddRequestTransform(async context =>
                {
                    var googleCredentials = GoogleCredential.GetApplicationDefault();
                    string accessToken = await googleCredentials.UnderlyingCredential.GetAccessTokenForRequestAsync();
                    context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                });
            }
        }

        builderContext.AddResponseTransform(async responseContext =>
        {
            if (responseContext.HttpContext.Request.Path == "/fhir/r4/metadata")
            {
                responseContext.SuppressResponseBody = true;
                var cache = responseContext.HttpContext.RequestServices.GetRequiredService<IFusionCache>();
                var bytes = await cache.GetOrSetAsync("metadata", _ => GetFhirMetadata(responseContext, builder));

                // Change Content-Length to match the modified body, or remove it.
                responseContext.HttpContext.Response.ContentLength = bytes?.Length;
                // Response headers are copied before transforms are invoked, update any needed headers on the HttpContext.Response.
                await responseContext.HttpContext.Response.Body.WriteAsync(bytes);
            }
        });

        builderContext.AddResponseTransform(async responseContext =>
        {
            if (responseContext.HttpContext.Request.Path != "/fhir/r4/metadata" && responseContext.HttpContext.Request.Path.StartsWithSegments("/fhir/r4/"));
            {
                var stream = await responseContext.ProxyResponse!.Content.ReadAsStreamAsync();
                using var reader = new StreamReader(stream);
                // TODO: size limits, timeouts
                var body = await reader.ReadToEndAsync();
                responseContext.SuppressResponseBody = true;

                var finalBytes = Encoding.UTF8.GetBytes(body.Replace($"\"url\": \"{builder.Configuration["FhirUrlProxy:Back"]}",
                    $"\"url\": \"{builder.Configuration["FhirUrlProxy:Front"]}"));
                responseContext.HttpContext.Response.ContentLength = finalBytes.Length;

                await responseContext.HttpContext.Response.Body.WriteAsync(finalBytes);
            }
        });
    });

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseDefaultFiles();
app.UseStaticFiles();


app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy();

app.UseSmartMetadata();
app.UseUdapMetadataServer("fhir/r4"); // Ensure metadata can only be called from this base URL.

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


async Task<string> UdapMedatData(string s)
{
    return s;
}

async Task<byte[]?> GetFhirMetadata(ResponseTransformContext responseTransformContext,
    WebApplicationBuilder webApplicationBuilder)
{
    var stream = await responseTransformContext.ProxyResponse.Content.ReadAsStreamAsync();
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