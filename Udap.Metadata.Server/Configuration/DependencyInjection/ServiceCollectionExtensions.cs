﻿#region (c) 2024 Joseph Shook. All rights reserved.
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
using Hl7.Fhir.Utility;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Metadata;
using Udap.Metadata.Server;
using Udap.Model;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddUdapMetadataServer(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        return AddUdapMetadataServer<UdapMetadataOptions, UdapMetadata>(services, configuration);
    }

    public static IServiceCollection AddUdapMetadataServer<TUdapMetadataOptions, TUdapMetadata>(
        this IServiceCollection services,
        IConfiguration configuration)
    where TUdapMetadataOptions : UdapMetadataOptions
    where TUdapMetadata : UdapMetadata
    {
        services.TryAddSingleton<IPrivateCertificateStore>(sp =>
            new IssuedCertificateStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                sp.GetRequiredService<ILogger<IssuedCertificateStore>>()));

        services.Configure<TUdapMetadataOptions>(configuration.GetSection("UdapMetadataOptions"));
        services.TryAddScoped<UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata>>();
        services.AddScoped<UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata>>();

        return services;
    }

    public static WebApplication UseUdapMetadataServer(this WebApplication app, string? prefixRoute = null)
    {
        return UseUdapMetadataServer<UdapMetadataOptions, UdapMetadata>(app, prefixRoute);
    }

    public static WebApplication UseUdapMetadataServer<TUdapMetadataOptions, TUdapMetadata>(this WebApplication app, string? prefixRoute = null)
        where TUdapMetadataOptions : UdapMetadataOptions
        where TUdapMetadata : UdapMetadata
    {
        app.MapGet($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{UdapConstants.Discovery.DiscoveryEndpoint}", (
                    [FromServices] UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata> endpoint,
                    HttpContext httpContext,
                    [FromQuery] string? community,
                    CancellationToken token) => endpoint.Process(httpContext, community, token))
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist

        app.MapGet($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{UdapConstants.Discovery.DiscoveryEndpoint}/communities",
                ([FromServices] UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata> endpoint) => endpoint.GetCommunities())
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist

        app.MapGet($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{UdapConstants.Discovery.DiscoveryEndpoint}/communities/ashtml",
                (
                    [FromServices] UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata> endpoint,
                    HttpContext httpContext) => endpoint.GetCommunitiesAsHtml(httpContext))
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist

        return app;
    }

    public static IApplicationBuilder UseUdapMetadataServer(this IApplicationBuilder app, string? prefixRoute = null)
    {
        return UseUdapMetadataServer<UdapMetadataOptions, UdapMetadata>(app, prefixRoute);
    }

    public static IApplicationBuilder UseUdapMetadataServer<TUdapMetadataOptions, TUdapMetadata>(this IApplicationBuilder app, string? prefixRoute = null)
        where TUdapMetadataOptions : UdapMetadataOptions
        where TUdapMetadata : UdapMetadata
    {

        app.Map($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{UdapConstants.Discovery.DiscoveryEndpoint}", path =>
        {
            path.Run(async ctx =>
            {
                var endpoint = ctx.RequestServices.GetRequiredService<UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata>>();
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
}
