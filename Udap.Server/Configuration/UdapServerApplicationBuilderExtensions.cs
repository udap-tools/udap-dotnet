#region (c) 2023 Joseph Shook. All rights reserved.
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
using Udap.Server.Hosting;
using Udap.Server.Registration;

namespace Udap.Server.Configuration;
public static class UdapServerApplicationBuilderExtensions
{
    public static IApplicationBuilder UseUdapServer(this WebApplication app)
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
                    //TODO:  Tests and response codes needed...    httpContext.Response
                    await endpoint.Process(httpContext, token);
                })
            .AllowAnonymous()
            .Produces(StatusCodes.Status201Created)
            .Produces(StatusCodes.Status401Unauthorized);

        return app;
    }
}
