#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics.CodeAnalysis;
using Hl7.Fhir.Utility;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.CdsHooks.Endpoint;
using Udap.CdsHooks.Model;
using Udap.Common.Extensions;

// ReSharper disable once CheckNamespace
#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Extension method used to register a single <see cref="CdsServices"/> or a named <see cref="CdsServices"/>.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddCdsServices(this IServiceCollection services)
    {
        services.AddScoped<CdsHooksEndpoint>(sp => 
            new CdsHooksEndpoint(sp.GetService<IOptionsMonitor<CdsServices>>(),
                sp.GetRequiredService<ILogger<CdsHooksEndpoint>>()));
        return services;
    }

    /// <summary>
    /// Extension method used to register a single <see cref="CdsServices"/> or a named <see cref="CdsServices"/>.
    /// This method will look up SMART Metadata from the "CdsServices" configuration section of appsettings.
    /// </summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static IHostApplicationBuilder AddCdsServices(this IHostApplicationBuilder builder)
    {
        builder.Services.Configure<CdsServices>(builder.Configuration.GetRequiredSection("CdsServices"));
        builder.Services.AddScoped<CdsHooksEndpoint>(sp =>
            new CdsHooksEndpoint(sp.GetService<IOptionsMonitor<CdsServices>>(),
                sp.GetRequiredService<ILogger<CdsHooksEndpoint>>()));

        return builder;
    }

    public static IApplicationBuilder UseCdsServices(this WebApplication app, string? prefixRoute = null)
    {
        var baseRoute = $"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{CdsConstants.Discovery.DiscoveryEndpoint}";

        app.MapGet(baseRoute, async ([FromServices] CdsHooksEndpoint endpoint) => await endpoint.Process())
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // missing CdsServices

        app.MapMethods(baseRoute, new[] { "OPTIONS" }, async context =>
        {
            // Inform the client about the allowed HTTP methods
            context.Response.Headers.Append("Allow", "GET, OPTIONS");
        
            // Specify which origins are allowed to access the resource
            context.Response.Headers.Append("Access-Control-Allow-Origin", "*"); // Adjust as needed
        
            // Specify the allowed HTTP methods for CORS
            context.Response.Headers.Append("Access-Control-Allow-Methods", "GET, OPTIONS");
        
            // Specify the allowed headers for CORS
            context.Response.Headers.Append("Access-Control-Allow-Headers", "Content-Type, Authorization");
        
            // Set the status code to 204 No Content
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            await context.Response.CompleteAsync();
        });

        var cdsServices = app.Services.GetRequiredService<IOptionsMonitor<CdsServices>>().CurrentValue;

        if (cdsServices.Services != null)
        {
            foreach (var service in cdsServices.Services)
            {
                var postRoute = $"{baseRoute}/{service.Id}";

                app.MapPost(postRoute, 
                        async (HttpRequest request, [FromServices] CdsHooksEndpoint endpoint) => 
                    await endpoint.ProcessPost(request))
                    .AllowAnonymous()
                    .Produces(StatusCodes.Status200OK)
                    .Produces(StatusCodes.Status404NotFound); // missing CdsServices
            }
        }

        return app;
    }
}
