#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text.Json;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Udap.Server.Hosting;
internal class UdapTokenResponseMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IdentityServerOptions _options;
    private readonly ILogger<UdapAuthorizationResponseMiddleware> _logger;

    public UdapTokenResponseMiddleware(
        RequestDelegate next,
        IdentityServerOptions options,
        ILogger<UdapAuthorizationResponseMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    public async Task Invoke(
        HttpContext context, 
        IClientStore clients, 
        IIdentityServerInteractionService interactionService)
    {
        context.Response.OnStarting(async () =>
        {
            if (context.Request.Path.Value != null && 
                context.Request.Path.Value.Contains("connect/authorize") &&
                context.Response.StatusCode == (int)HttpStatusCode.Redirect &&
                !context.Response.Headers.Location.IsNullOrEmpty()
                )
            {
                var query = new Uri(context.Response.Headers.Location!).Query;
                var responseParams = QueryHelpers.ParseQuery(query);
                 

                if (responseParams.TryGetValue(_options.UserInteraction.ErrorIdParameter, out var errorId))
                {
                    var requestParams = context.Request.Query.AsNameValueCollection();
                    var client = await clients.FindClientByIdAsync(requestParams.Get("client_id"));
                    var scope = requestParams.Get("scope");

                    if (client == null && scope != null && scope.Contains("udap"))
                    {
                        await RenderErrorResponse(context.Response, interactionService, errorId);
                    }

                    if (client != null && 
                        client.ClientSecrets.Any(cs =>
                            cs.Type == UdapServerConstants.SecretTypes.Udap_X509_Pem))
                    {
                        await RenderErrorResponse(context.Response, interactionService, errorId);
                    }
                }
            }
        });

        await _next(context);
    }

    private async Task RenderErrorResponse(
        HttpResponse response, 
        IIdentityServerInteractionService 
            interactionService, StringValues errorId)
    {
        var errorMessage = await interactionService.GetErrorContextAsync(errorId);
        response.StatusCode = (int)HttpStatusCode.BadRequest;
        await response.WriteAsJsonAsync(errorMessage);
        await response.Body.FlushAsync();
    }
}
