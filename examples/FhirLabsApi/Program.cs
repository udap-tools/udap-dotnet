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
using Hl7.Fhir.DemoFileSystemFhirServer;
using Hl7.Fhir.NetCoreApi;
using Hl7.Fhir.WebApi;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Udap.Common;
using Udap.Metadata.Server;

var builder = WebApplication.CreateBuilder(args);


builder.WebHost.UseKestrel((b, so) =>
{
    

    so.ListenAnyIP(7016, listenOpt =>
    {
        listenOpt.UseHttps(
            Path.Combine(
                Path.GetDirectoryName(typeof(Program).Assembly.Location) ?? string.Empty, 
                b.Configuration["SslFileLocation"]),
            b.Configuration["CertPassword"]);
    });

    so.ListenAnyIP(5016);

});


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


// UDAP CertStore
builder.Services.Configure<UdapFileCertStoreManifest>(builder.Configuration.GetSection("UdapFileCertStoreManifest"));
builder.Services.AddSingleton<ICertificateStore>(sp =>
    new FileCertificateStore(
        sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(), 
        sp.GetRequiredService<ILogger<FileCertificateStore>>(),
        "FhirLabsApi"));


//
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
//
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UsePathBase(new PathString("/fhir/r4"));


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

app.UseSwagger();
app.UseSwaggerUI(options => {
    options.SwaggerEndpoint("v1/swagger.json", "FhirLabs V1");
});

app.UseRouting();


app.UseHttpsRedirection();


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


app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// app.UseEndpoints(endpoints =>
// {
//     endpoints.MapSwagger();
// });


app.Run();


//
// Accessible to unit tests
//


namespace FhirLabsApi
{
    public partial class Program { }
}
