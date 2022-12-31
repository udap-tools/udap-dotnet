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
using Hl7.Fhir.WebApi;
using IdentityModel;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Serilog;
using Udap.Common;
using Udap.Metadata.Server;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddUserSecrets<Program>(optional:true);  // I want user secrets even in release mode.

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


builder.Services
    
    .UseFhirServerController( /*systemService,*/ options =>
    {
        // An example HTML formatter that puts the raw XML on the output
        options.OutputFormatters.Add(new SimpleHtmlFhirOutputFormatter());
        // need this to serialize udap metadata becaue UseFhirServerController clears OutputFormatters
        options.OutputFormatters.Add(new SystemTextJsonOutputFormatter(new JsonSerializerOptions()));
    })
    .UseUdapMetaDataServer(builder.Configuration)
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.ContractResolver = new DefaultContractResolver
        {
            NamingStrategy = new SnakeCaseNamingStrategy(),

        };
        options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
        options.SerializerSettings.Formatting = Formatting.Indented;
    });

builder.Services.AddAuthentication(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)

    .AddJwtBearer(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, options =>
    {
        //TODO move this to config file.  Do it today!

        options.Authority = builder.Configuration["Jwt:Authority"];
        // options.RequireHttpsMetadata = bool.Parse(builder.Configuration["Jwt:RequireHttpsMetadata"]);
        
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
    });
    

// UDAP CertStore
builder.Services.Configure<UdapFileCertStoreManifest>(GetUdapFileCertStoreManifest(builder));
builder.Services.AddSingleton<ICertificateStore>(sp =>
    new FileCertificateStore(
        sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(), 
        sp.GetRequiredService<ILogger<FileCertificateStore>>(),
        "FhirLabsApi"));


builder.AddRateLimiting();

var app = builder.Build();

// Configure the HTTP request pipeline.

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


app.UseRateLimiter();

// app.UseHttpsRedirection();

//
// Diagram to decide where cors middleware should be applied.
// https://docs.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-6.0#middleware-order
//
app.UseCors(config =>
{
    // config.WithOrigins(settings.AllowedOrigins);
    config.AllowAnyOrigin();
    config.AllowAnyMethod();
    config.AllowAnyHeader();
    config.WithExposedHeaders("Content-Location", "Location", "Etag" );
});



app.MapControllers()
    .RequireAuthorization()
    .RequireRateLimiting(RateLimitExtensions.GetPolicy);

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

        var secretResource = "projects/341821616593/secrets/UdapFileCertStoreManifest/versions/latest";

        Log.Logger.Information("Requesting {secretResource");
        // Call the API.
        var result = client.AccessSecretVersion(secretResource);

        // Convert the payload to a string. Payloads are bytes by default.
        MemoryStream stream = new MemoryStream(result.Payload.Data.ToByteArray());
       
        
        webApplicationBuilder.Configuration.AddJsonStream(stream);
    }

    return webApplicationBuilder.Configuration.GetSection("UdapFileCertStoreManifest");
}

Stream GenerateStreamFromString(string s)
{
    var stream = new MemoryStream();
    var writer = new StreamWriter(stream);
    writer.Write(s);
    writer.Flush();
    stream.Position = 0;
    return stream;
}

//
// Accessible to unit tests
//


namespace FhirLabsApi
{
    public partial class Program { }
}
