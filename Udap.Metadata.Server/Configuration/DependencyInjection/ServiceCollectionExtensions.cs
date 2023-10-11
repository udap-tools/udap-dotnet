#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion



//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net.Http;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Metadata.Server;
using Udap.Model;
using Constants = Udap.Common.Constants;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{

    /// <summary>
    /// Extension method used to register a <see cref="UdapFileCertStoreManifest"/> that is built by the
    /// deserialized of configuration data stored in appsettings.json.  The name in appsettings.json
    /// is identified by the string defined in <see cref="Constants.UDAP_FILE_STORE_MANIFEST"/>
    /// </summary>
    /// <param name="mvcBuilder"></param>
    /// <param name="configuration"></param>
    /// <param name="applicationName"></param>
    /// <returns></returns>
    public static IMvcBuilder AddUdapMetaDataServer(
        this IMvcBuilder mvcBuilder,
        ConfigurationManager configuration,
        string? applicationName = null)
    {
        var udapMetadataOptions = configuration.GetRequiredSection("UdapMetadataOptions")
            .Get<UdapMetadataOptions>();

        var udapMetadata = new UdapMetadata(
            udapMetadataOptions!,
            Hl7ModelInfoExtensions
                .BuildHl7FhirV1AndV2Scopes(new List<string> { "patient", "user", "system" })
                .Where(s => s.Contains("/*")) //Just show the wild card
        );

        mvcBuilder.Services.TryAddSingleton(udapMetadata);
        mvcBuilder.Services.TryAddScoped<UdapMetaDataBuilder>();

        if (mvcBuilder.Services.All(x => x.ServiceType != typeof(IPrivateCertificateStore)))
        {
            mvcBuilder.Services
                .Configure<UdapFileCertStoreManifest>(configuration
                    .GetSection(Constants.UDAP_FILE_STORE_MANIFEST));

            mvcBuilder.Services.AddSingleton<IPrivateCertificateStore>(sp =>
                new IssuedCertificateStore(
                    sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                    sp.GetRequiredService<ILogger<IssuedCertificateStore>>(),
                    applicationName));
        }

        var assembly = typeof(UdapController).Assembly;
        return mvcBuilder.AddApplicationPart(assembly);
    }
    

    public static IServiceCollection AddUdapMetadataServer(
        this IServiceCollection services,
        IConfiguration configuration,
        string? applicationName = null)
    {
        var udapMetadataOptions = new UdapMetadataOptions();
        configuration.GetSection("UdapMetadataOptions").Bind(udapMetadataOptions);

        if (!udapMetadataOptions.Enabled)
            return services;
        
        services.Configure<UdapMetadataOptions>(configuration.GetSection("UdapMetadataOptions"));
        
        //TODO: this could use some DI work...
        var udapMetadata = new UdapMetadata(
            udapMetadataOptions!,
            new List<string>
            {
                "openid", "patient/*.read", "user/*.read", "system/*.read", "patient/*.rs", "user/*.rs", "system/*.rs"
            });

        services.AddSingleton(udapMetadata);
        services.TryAddScoped<UdapMetaDataBuilder>();
        services.AddScoped<UdapMetaDataEndpoint>();

        if(services.All(x => x.ServiceType != typeof(IPrivateCertificateStore)))
        {
            services.Configure<UdapFileCertStoreManifest>(
                configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));

            services.TryAddSingleton<IPrivateCertificateStore>(sp =>
                new IssuedCertificateStore(
                    sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                    sp.GetRequiredService<ILogger<IssuedCertificateStore>>(),
                    applicationName));
        }

        return services;
    }



    public static IApplicationBuilder UseUdapMetadataServer(this WebApplication app)
    {
        EnsureMvcControllerUnloads(app);

        app.MapGet($"/{UdapConstants.Discovery.DiscoveryEndpoint}",
                async (
                    [FromServices] UdapMetaDataEndpoint endpoint,
                    HttpContext httpContext,
                    [FromQuery] string? community,
                    CancellationToken token) => await endpoint.Process(httpContext, community, token))
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist

        app.MapGet($"/{UdapConstants.Discovery.DiscoveryEndpoint}/communities",
                ([FromServices] UdapMetaDataEndpoint endpoint) => endpoint.GetCommunities())
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist

        app.MapGet($"/{UdapConstants.Discovery.DiscoveryEndpoint}/communities/ashtml",
                (
                    [FromServices] UdapMetaDataEndpoint endpoint,
                    HttpContext httpContext) => endpoint.GetCommunitiesAsHtml(httpContext))
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist

        return app;
    }

    public static IApplicationBuilder UseUdapMetadataServer(this IApplicationBuilder app)
    {

        app.Map($"/{UdapConstants.Discovery.DiscoveryEndpoint}", path =>
        {
            path.Run(async ctx =>
            {
                var endpoint = ctx.RequestServices.GetRequiredService<UdapMetaDataEndpoint>();
                var result = await endpoint.Process(ctx, null, default);
                if (result != null)
                {
                    await result.ExecuteAsync(ctx);
                }
                else
                {
                    ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
                }
            });
        });
        
        return app;
    }

    private static void EnsureMvcControllerUnloads(WebApplication app)
    {
        if (app.Services.GetService(typeof(ApplicationPartManager)) is ApplicationPartManager appPartManager)
        {
            var part = appPartManager.ApplicationParts.FirstOrDefault(a => a.Name == "Udap.Metadata.Server");
            if (part != null)
            {
                appPartManager.ApplicationParts.Remove(part);
            }
        }
    }
}
