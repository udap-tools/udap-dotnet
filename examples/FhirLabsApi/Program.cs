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
using Hl7.Fhir.DemoFileSystemFhirServer;
using Hl7.Fhir.NetCoreApi;
using Hl7.Fhir.Utility;
using Hl7.Fhir.WebApi;
using IdentityModel;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Serilog;
using Udap.Common;
using Udap.Common.Certificates;
using Constants = Udap.Common.Constants;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddUserSecrets<Program>(optional:true);  // I want user secrets even in release mode.

builder.Host.UseSerilog((ctx, lc) => lc
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
    .Enrich.FromLogContext()
    .ReadFrom.Configuration(ctx.Configuration));

// Add services to the container.

builder.Configuration.AddJsonFile("/secret/fhirlabs_appsettings", true, false);

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

builder.Services
    .UseFhirServerController( /*systemService,*/ options =>
    {
        // An example HTML formatter that puts the raw XML on the output
        options.OutputFormatters.Add(new SimpleHtmlFhirOutputFormatter());
        // need this to serialize udap metadata because UseFhirServerController clears OutputFormatters
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


builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
builder.Services.AddSingleton<IPrivateCertificateStore>(sp =>
    new IssuedCertificateStore(
        sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(), 
        sp.GetRequiredService<ILogger<IssuedCertificateStore>>(),
        "FhirLabsApi"));

builder.Services.AddUdapMetadataServer(builder.Configuration);


builder.AddRateLimiting();


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
app.UseRateLimiter();

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
    .RequireAuthorization()
    .RequireRateLimiting(RateLimitExtensions.GetPolicy);

app.Run();

//
// Accessible to unit tests
//
namespace FhirLabsApi
{
    public partial class Program { }
}
