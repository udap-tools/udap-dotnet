#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text.Json;
using FhirLabsApi;
using FhirLabsApi.Extensions;
using Google.Cloud.SecretManager.V1;
using Hl7.Fhir.DemoFileSystemFhirServer;
using Hl7.Fhir.NetCoreApi;
using Hl7.Fhir.Utility;
using Hl7.Fhir.WebApi;
using IdentityModel;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Serilog;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Metadata.Server;
using Udap.Model;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddUserSecrets<Program>(optional:true);  // I want user secrets even in release mode.

builder.Host.UseSerilog((ctx, lc) => lc
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
    .Enrich.FromLogContext()
    .ReadFrom.Configuration(ctx.Configuration));

// Add services to the container.

//
// TODO: I would rather do the following:
// builder.Services.Configure<ServerSettings>(builder.Configuration.GetSection("ServerSettings"));
// Then have ServerSettings be injected into DirectorySystemService and let it check to see if 
// directory exists and eliminate the Directory static prop.
// 
// Maybe a PR to Brian in the future.
//
var settings = builder.Configuration.GetOption<ServerSettings>("ServerSettings");

DirectorySystemService<IServiceProvider>.Directory = settings.ServerBaseDirectory;
if (!Directory.Exists(DirectorySystemService<IServiceProvider>.Directory))
    Directory.CreateDirectory(DirectorySystemService<IServiceProvider>.Directory);

//
// s is unused.  Maybe the TODO above would make this go away.  
//
builder.Services.AddSingleton<IFhirSystemServiceR4<IServiceProvider>>(s => {
    var systemService = new DirectorySystemService<IServiceProvider>();
    systemService.InitializeIndexes();
    return systemService;
});

var udapConfig = builder.Configuration.GetRequiredSection("UdapConfig").Get<UdapConfig>();

var udapMetadata = new UdapMetadata(
    udapConfig!, 
    Hl7ModelInfoExtensions
        .BuildHl7FhirV1AndV2Scopes(new List<string>{"patient", "user", "system"} )
        .Where(s => s.Contains("/*")) //Just show the wild card
    );

builder.Services.AddSingleton(udapMetadata);
builder.Services.TryAddScoped<UdapMetaDataBuilder>();
builder.Services.AddScoped<UdapMetaDataEndpoint>();

builder.Services
    .UseFhirServerController( /*systemService,*/ options =>
    {
        // An example HTML formatter that puts the raw XML on the output
        options.OutputFormatters.Add(new SimpleHtmlFhirOutputFormatter());
        // need this to serialize udap metadata becaue UseFhirServerController clears OutputFormatters
        options.OutputFormatters.Add(new SystemTextJsonOutputFormatter(new JsonSerializerOptions()));
        
    })
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.ContractResolver = new DefaultContractResolver
        {
            NamingStrategy = new SnakeCaseNamingStrategy(),
    
        };
        options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
        options.SerializerSettings.Formatting = Formatting.Indented;
    })
    ;

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
    

// UDAP CertStore
builder.Services.Configure<UdapFileCertStoreManifest>(GetUdapFileCertStoreManifest(builder));
builder.Services.AddSingleton<IPrivateCertificateStore>(sp =>
    new IssuedCertificateStore(
        sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(), 
        sp.GetRequiredService<ILogger<IssuedCertificateStore>>(),
        "FhirLabsApi"));


// builder.AddRateLimiting();


builder.Services.AddTransient<FhirSmartAppLaunchConfiguration>(options =>
{
    var result = new FhirSmartAppLaunchConfiguration();
    var authBaseAddress = $"{builder.Configuration["Jwt:Authority"].EnsureEndsWith("/")}connect/";
    result.authorization_endpoint = $"{authBaseAddress}authorize";
    result.token_endpoint = $"{authBaseAddress}token";

    result.introspection_endpoint = $"{authBaseAddress}introspect";
    result.revocation_endpoint = $"{authBaseAddress}revocation";
    result.token_endpoint_auth_methods_supported = new string[] { "client_secret_basic", "client_secret_post" };
    result.scopes_supported = new string[] { "openid", "profile", "launch", "patient/*.*", "user/*.*", "system/*.*", "offline_access" };
    result.response_types_supported = new string[] { "code", "code id_token", "id_token", "refresh_token" };
    result.capabilities = new string[] { "launch-ehr", "launch-standalone", "client-public", "client-confidential-symmetric" };
    result.code_challenge_methods_supported = new[] { "S256" };

    return result;
});


var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseSerilogRequestLogging();
// app.UseRateLimiter();

app.UsePathBase(new PathString("/fhir/r4"));

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    if (!context.Request.PathBase.HasValue)
    {
        if (context.Request.Path.HasValue && context.Request.Path.Value == "/")
        {
            context.Response.Redirect("/fhir/r4");
            await context.Response.CompleteAsync();
            return;
        }

        if (context.Request.Path.HasValue && context.Request.Path.Value == "/metadata")
        {
            context.Response.Redirect("/fhir/r4/metadata");
            await context.Response.CompleteAsync();
            return;
        }
        
        context.Response.StatusCode = (int)HttpStatusCode.NotFound;
        await context.Response.CompleteAsync();
        return;
    }
    await next.Invoke();
});

app.UseHttpsRedirection();

//
// Diagram to decide where cors middleware should be applied.
// https://docs.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-6.0#middleware-order
//
app.UseCors();

app.UseUdapMetadataServer();

app.MapFhirSmartAppLaunchController();
app.MapControllers()
    .RequireAuthorization();
    // .RequireRateLimiting(RateLimitExtensions.GetPolicy);


app.Run();

IConfigurationSection GetUdapFileCertStoreManifest(WebApplicationBuilder webApplicationBuilder)
{
    //Ugly but works so far.
    if (Environment.GetEnvironmentVariable("GCLOUD_PROJECT") != null)
    {
        // Log.Logger.Information("Loading connection string from gcp_db");
        // connectionString = Environment.GetEnvironmentVariable("gcp_db");
        // Log.Logger.Information($"Loaded connection string, length:: {connectionString?.Length}");

        Log.Logger.Information("Creating client");
        var client = SecretManagerServiceClient.Create();
        
        var secretResource = "projects/288013792534/secrets/UdapFileCertStoreManifest/versions/latest";

        Log.Logger.Information("Requesting {secretResource");
        // Call the API.
        var result = client.AccessSecretVersion(secretResource);

        // Convert the payload to a string. Payloads are bytes by default.
        var stream = new MemoryStream(result.Payload.Data.ToByteArray());
       
        
        webApplicationBuilder.Configuration.AddJsonStream(stream);
    }

    return webApplicationBuilder.Configuration.GetSection("UdapFileCertStoreManifest");
}


//
// Accessible to unit tests
//
namespace FhirLabsApi
{
    public partial class Program { }
}
