#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.Metadata.Server;
using Udap.Model;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//

namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    // TODO this is not flexible to work with implementations that do not use UdapConfig in appsettings.

    public static IMvcBuilder AddUdapMetaDataServer(
        this IMvcBuilder mvcBuilder,
        ConfigurationManager configuration)
    {
        var services = mvcBuilder.Services;
        services.Configure<UdapConfig>(configuration.GetSection("UdapConfig"));
        mvcBuilder.Services.TryAddSingleton<UdapMetadata>();
        mvcBuilder.Services.TryAddSingleton<UdapMetaDataBuilder>();

        var assembly = typeof(UdapController).Assembly;
        return mvcBuilder.AddApplicationPart(assembly);
    }

    public static IApplicationBuilder UseUdapMetadataServer(this WebApplication app)
    {
        EnsureMvcControllerUnloads(app);

        app.MapGet($"/{UdapConstants.Discovery.DiscoveryEndpoint}", 
                async (
                    [FromServices] UdapMetaDataEndpoint endpoint,
                    HttpContext httpContext,
                    [FromQuery]string? community,
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

    private static void EnsureMvcControllerUnloads(WebApplication app)
    {
        if (app.Services.GetService(typeof(ApplicationPartManager)) is ApplicationPartManager appPartManager)
        {
            var part = appPartManager?.ApplicationParts.FirstOrDefault(a => a.Name == "Udap.Metadata.Server");
            if (part != null)
            {
                appPartManager.ApplicationParts.Remove(part);
            }
        }
    }
}

