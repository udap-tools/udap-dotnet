#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Udap.Server.Hosting;
using Udap.Server.Registration;

// ReSharper disable once CheckNamespace
#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.AspNetCore.Builder;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static class UdapServerApplicationBuilderExtensions
{
    public static IApplicationBuilder UseUdapServer(this WebApplication app)
    {
        app.UseMiddleware<UdapTokenResponseMiddleware>();
        app.UseMiddleware<UdapScopeEnrichmentMiddleware>();
        app.UseMiddleware<UdapAuthorizationResponseMiddleware>();
        // app.UseMiddleware<UdapTieredOAuthMiddleware>();

        app.MapPost("/connect/register",
                async (
                    HttpContext httpContext,
                    [FromServices] UdapDynamicClientRegistrationEndpoint endpoint,
                    CancellationToken token) =>
                {
                    await endpoint.Process(httpContext, token);
                })
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status400BadRequest);

        return app;
    }

    public static IApplicationBuilder UseUdapServer(this IApplicationBuilder app)
    {
        app.UseMiddleware<UdapTokenResponseMiddleware>();
        app.UseMiddleware<UdapScopeEnrichmentMiddleware>();
        app.UseMiddleware<UdapAuthorizationResponseMiddleware>();
        // app.UseMiddleware<UdapTieredOAuthMiddleware>();

        return app;
    }

    public static IApplicationBuilder UseUdapIdPServer(this WebApplication app)
    {
        app.UseMiddleware<UdapTokenResponseMiddleware>();
        app.UseMiddleware<UdapScopeEnrichmentMiddleware>();
        app.UseMiddleware<UdapAuthorizationResponseMiddleware>();
        

        app.MapPost("/connect/register",
                async (
                    HttpContext httpContext,
                    [FromServices] UdapDynamicClientRegistrationEndpoint endpoint,
                    CancellationToken token) =>
                {
                    await endpoint.Process(httpContext, token);
                })
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status400BadRequest);

        return app;
    }

    public static IApplicationBuilder UseUdapIdPServer(this IApplicationBuilder app)
    {
        app.UseMiddleware<UdapTokenResponseMiddleware>();
        app.UseMiddleware<UdapScopeEnrichmentMiddleware>();
        app.UseMiddleware<UdapAuthorizationResponseMiddleware>();

        return app;
    }
}
