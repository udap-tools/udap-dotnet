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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Hl7.Fhir.Utility;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Metadata;
using Udap.Metadata.Server;
using Udap.Model;
using Constants = Udap.Common.Constants;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddUdapMetadataServer(
        this IServiceCollection services,
        IConfiguration configuration,
        string? applicationName = null)
    {
        var udapMetadataOptions = new UdapMetadataOptions();
        configuration.GetSection("UdapMetadataOptions").Bind(udapMetadataOptions);

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
        
        return services;
    }
    

     public static WebApplication UseUdapMetadataServer(this WebApplication app, string? prefixRoute = null)
    {
        app.MapGet($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{UdapConstants.Discovery.DiscoveryEndpoint}", (
                    [FromServices] UdapMetaDataEndpoint endpoint,
                    HttpContext httpContext,
                    [FromQuery] string? community,
                    CancellationToken token) => endpoint.Process(httpContext, community, token))
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist
    
        app.MapGet($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{UdapConstants.Discovery.DiscoveryEndpoint}/communities",
                ([FromServices] UdapMetaDataEndpoint endpoint) => endpoint.GetCommunities())
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist
    
        app.MapGet($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{UdapConstants.Discovery.DiscoveryEndpoint}/communities/ashtml",
                (
                    [FromServices] UdapMetaDataEndpoint endpoint,
                    HttpContext httpContext) => endpoint.GetCommunitiesAsHtml(httpContext))
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound); // community doesn't exist
    
        return app;
    }

    public static IApplicationBuilder UseUdapMetadataServer(this IApplicationBuilder app, string? prefixRoute = null)
    {

        app.Map($"/{prefixRoute?.EnsureTrailingSlash().RemovePrefix("/")}{UdapConstants.Discovery.DiscoveryEndpoint}", path =>
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
}
