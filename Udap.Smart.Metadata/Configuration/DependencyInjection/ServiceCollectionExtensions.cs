#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Utility;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Udap.Common.Extensions;
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
    /// <returns></returns>
    public static IServiceCollection AddSmartMetadata(this IServiceCollection services)
    {
        services.AddScoped<SmartMetadataEndpoint>(sp => 
            new SmartMetadataEndpoint(sp.GetService<IOptionsMonitor<SmartMetadata>>()));
        return services;
    }

    /// <summary>
    /// Extension method used to register a single <see cref="SmartMetadata"/> or a named <see cref="SmartMetadata"/>.
    /// This method will look up SMART Metadata from the "SmartMetadata" configuration section of appsettings.
    /// </summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static IHostApplicationBuilder AddSmartMetadata(this IHostApplicationBuilder builder)
    {
        builder.Services.Configure<SmartMetadata>(builder.Configuration.GetRequiredSection("SmartMetadata"));
        builder.Services.AddScoped<SmartMetadataEndpoint>(sp =>
            new SmartMetadataEndpoint(sp.GetService<IOptionsMonitor<SmartMetadata>>()));

        return builder;
    }

    public static IApplicationBuilder UseSmartMetadata(this WebApplication app, string? prefixRoute = null)
    {
        app.MapGet($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{SmartConstants.Discovery.DiscoveryEndpoint}",
                async ([FromServices] SmartMetadataEndpoint endpoint) => await endpoint.Process())
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // missing SmartMetadata
        
        return app;
    }
}
