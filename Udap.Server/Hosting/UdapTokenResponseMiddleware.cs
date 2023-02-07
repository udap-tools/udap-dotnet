#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Org.BouncyCastle.Asn1.Ocsp;

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
                context.Request.Path.Value.Contains(Constants.ProtocolRoutePaths.Authorize) &&
                context.Response.StatusCode == (int)HttpStatusCode.Redirect &&
                !context.Response.Headers.Location.IsNullOrEmpty()
                )
            {
                var uri = new Uri(context.Response.Headers.Location!);
                var query = uri.Query;
                var responseParams = QueryHelpers.ParseQuery(query);


                if (responseParams.TryGetValue(_options.UserInteraction.ErrorIdParameter, out var errorId))
                {
                    var requestParams = context.Request.Query.AsNameValueCollection();
                    var client = await clients.FindClientByIdAsync(requestParams.Get(OidcConstants.AuthorizeRequest.ClientId));
                    var scope = requestParams.Get(OidcConstants.AuthorizeRequest.Scope);

                    if (client == null && scope != null && scope.Contains("udap"))
                    {
                        await RenderErrorResponse(context, uri, query, interactionService, errorId);
                    }

                    if (client != null &&
                        client.ClientSecrets.Any(cs =>
                            cs.Type == UdapServerConstants.SecretTypes.Udap_X509_Pem))
                    {
                        await RenderErrorResponse(context, uri, query, interactionService, errorId);
                    }
                }
            }
        });

        await _next(context);
    }

    private async Task RenderErrorResponse(
        HttpContext context,
        Uri uri,
        string query,
        IIdentityServerInteractionService interactionService,
        StringValues errorId)
    {
        var errorMessage = await interactionService.GetErrorContextAsync(errorId);

        if (errorMessage.Error == OidcConstants.AuthorizeErrors.UnsupportedResponseType)
        {
            //
            // Include error in redirect
            //

            var sb = new StringBuilder();

            if (context.Request.Query.TryGetValue(
                    OidcConstants.AuthorizeRequest.RedirectUri,
                    out StringValues redirectUri))
            {
                sb.Append(redirectUri).Append("?");

                sb.Append(OidcConstants.AuthorizeResponse.Error)
                    .Append("=")
                    .Append(errorMessage.Error);

                sb.Append("&")
                    .Append(OidcConstants.AuthorizeResponse.ErrorDescription)
                    .Append("=")
                    .Append(errorMessage.ErrorDescription);

                if (context.Request.Query.TryGetValue(
                        OidcConstants.AuthorizeRequest.ResponseType,
                        out StringValues responseType))
                {
                    sb.Append("&")
                        .Append(OidcConstants.AuthorizeRequest.ResponseType)
                        .Append("=")
                        .Append(responseType);
                }

                if (context.Request.Query.TryGetValue(
                        OidcConstants.AuthorizeRequest.Scope,
                        out StringValues scope))
                {
                    sb.Append("&")
                        .Append(OidcConstants.AuthorizeRequest.Scope)
                        .Append("=")
                        .Append(scope);
                }

                if (context.Request.Query.TryGetValue(
                        OidcConstants.AuthorizeRequest.State,
                        out StringValues state))
                {
                    sb.Append("&")
                        .Append(OidcConstants.AuthorizeRequest.State)
                        .Append("=")
                        .Append(state);
                }

                if (context.Request.Query.TryGetValue(
                        OidcConstants.AuthorizeRequest.Nonce,
                        out StringValues nonce))
                {
                    sb.Append("&")
                        .Append(OidcConstants.AuthorizeRequest.Nonce)
                        .Append("=")
                        .Append(nonce);
                }

                context.Response.Headers.Location = sb.ToString();
            }

            return;
        }

        //
        // 400 response
        //
        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await context.Response.WriteAsJsonAsync(errorMessage);
        await context.Response.Body.FlushAsync();
    }
}
