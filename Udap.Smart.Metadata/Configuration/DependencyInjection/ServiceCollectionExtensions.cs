#region (c) 2024 Joseph Shook. All rights reserved.
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
using Microsoft.Extensions.Options;
using Udap.Smart.Metadata;
using Udap.Smart.Model;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Extension method used to register a single <see cref="SmartMetadata"/> or a named <see cref="SmartMetadata"/>.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="namedOption">Named Option.  This feature is anticipated to allow a proxy server implementation to host multiple .well-known/smart-configuration endpoints.</param>
    /// <returns></returns>
    public static IServiceCollection AddSmartMetadata(this IServiceCollection services, string? namedOption = null)
    {
        services.AddScoped<SmartMetadataEndpoint>(sp => 
            new SmartMetadataEndpoint(sp.GetService<IOptionsMonitor<SmartMetadata>>(), namedOption));
        return services;
    }



     public static IApplicationBuilder UseSmartMetadata(this WebApplication app, string? prefixRoute = null)
    {
        EnsureMvcControllerUnloads(app);

        app.MapGet($"/{prefixRoute}{SmartConstants.Discovery.DiscoveryEndpoint}",
                async ([FromServices] SmartMetadataEndpoint endpoint) => await endpoint.Process())
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // missing SmartMetadata
        
        return app;
    }

    public static IApplicationBuilder UseSmartMetadata(this IApplicationBuilder app, string? prefixRoute = null)
    {
        app.Map($"/{prefixRoute}{SmartConstants.Discovery.DiscoveryEndpoint}", path =>
        {
            path.Run(async ctx =>
            {
                var endpoint = ctx.RequestServices.GetRequiredService<SmartMetadataEndpoint>();
                var result = await endpoint.Process();
                await result.ExecuteAsync(ctx);
            });
        });
        
        return app;
    }

    private static void EnsureMvcControllerUnloads(WebApplication app)
    {
        if (app.Services.GetService(typeof(ApplicationPartManager)) is ApplicationPartManager appPartManager)
        {
            var part = appPartManager.ApplicationParts.FirstOrDefault(a => a.Name == "Smart.Metadata.Server");
            if (part != null)
            {
                appPartManager.ApplicationParts.Remove(part);
            }
        }
    }
}
