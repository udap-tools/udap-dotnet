#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using IdentityModel.AspNetCore.OAuth2Introspection;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common;
using Udap.Metadata.Server;
using Udap.Model;

var builder = WebApplication.CreateBuilder(args);

//
// A technique to load ssl cert for Kestrel
//
// builder.WebHost.UseKestrel((b, so) =>
// {
//     so.ListenAnyIP(5021, listenOpt =>
//     {
//         listenOpt.UseHttps(
//             Path.Combine(
//                 Path.GetDirectoryName(typeof(Program).Assembly.Location) ?? string.Empty,
//                 b.Configuration["SslFileLocation"]),
//             b.Configuration["CertPassword"]);
//     });
//     so.ListenAnyIP(5020);
// });

// But I am choosing to just use my host.docker.internal.pfx ssl cert generated from the Udap.PKI.Generator test project
// It allows docker services to discover local running desktop services.  Obviously this comment is most appropriate for 
// something like finding Udap.Idp project running on the desktop from something like hte FhirLabsApi running in docker.
// This is a Windows thing for sure.  Not sure if what happens on a Mac.  
/*
  "Kestrel": {
    "Certificates": {
      "Default": {
        "Path": "host.docker.internal.pfx",
        "Password": "udap-test"
      }
    }
  },
 
*/


// Add services to the container.

var udapMetaData = MyCustomUdapMetadata.Build(builder.
    Configuration.GetSection("UdapConfig").Get<UdapConfig>());

builder.Services
    .AddControllers()
    .UseUdapMetaDataServer(builder.Configuration, udapMetaData);

    
// UDAP CertStore
builder.Services
    .Configure<UdapFileCertStoreManifest>(builder
        .Configuration.GetSection("UdapFileCertStoreManifest"));

builder.Services.AddSingleton<ICertificateStore>(sp => 
    new FileCertificateStore(
        sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(), 
        sp.GetRequiredService<ILogger<FileCertificateStore>>(),
        "WeatherApi"));

//builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    .AddJwtBearer(options =>
//    {
//        options.Authority = "https://https://udap.idp.securedcontrols.net:5002";
//        options.Audience = "weatherapi";
//        options.TokenValidationParameters = new TokenValidationParameters()
//        {
//            NameClaimType = "name",
//            ClockSkew = TimeSpan.FromSeconds(10) // Default is 5 minutes.  Tighten for dev testing.
//        };        
//    });

//
// https://docs.duendesoftware.com/identityserver/v5/apis/aspnetcore/reference/
//
builder.Services.AddAuthentication(OAuth2IntrospectionDefaults.AuthenticationScheme)
    .AddOAuth2Introspection(options =>
    {
        options.Authority = "https://udap.idp.securedcontrols.net:5002";
        options.ClientId = "weatherapi";
        options.ClientSecret = "weatherapi_secret";
    });


builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "WeatherApi", Version = "v1" });
});

var app = builder.Build();
app.UseRouting();

// Configure the HTTP request pipeline.
if (builder.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("v1/swagger.json", "WeatherApi v1");
    });
}

app.UseHttpsRedirection();

//
// Diagram to decide where cors middleware should be applied.
// https://docs.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-6.0#middleware-order
//
app.UseCors();


app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();


app.Run();

//
// Accessible to unit tests
//
namespace WeatherApi
{
    public partial class Program { }
}
