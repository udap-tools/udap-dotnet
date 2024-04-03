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
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Udap.Server.Configuration;
using static IdentityModel.OidcConstants;

namespace Udap.Server.Hosting;


/// <summary>
/// Identity Server by default responds with a redirect to /home/error/errorid=...
/// for all errors in response to failed /connect/authorize? requests.
///
/// UDAP is expecting 400-599 errors and or redirects to redirect_uri
/// with a error and error_description in the query params.
///
/// Require state parameter from clients by configuring the
/// <see cref="ServerSettings.ForceStateParamOnAuthorizationCode"/> to true.
/// </summary>
internal class UdapAuthorizationResponseMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IdentityServerOptions _options;
    private readonly ILogger<UdapTokenResponseMiddleware> _logger;

    public UdapAuthorizationResponseMiddleware(
        RequestDelegate next,
        IdentityServerOptions options,
        ILogger<UdapTokenResponseMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// During a Server request to "/authorize", while Server is configured for
    /// <see cref="ServerSettings.ForceStateParamOnAuthorizationCode"/>, and the
    /// state parameter is missing and client has a <see cref="Duende.IdentityServer.Models.Secret"/>
    /// of type  <see cref="UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME"/>
    ///
    /// Comment regarding missing state.  Requiring in UDAP to encourage CSRF protection.  The client
    /// is already required in section 10.12 of RFC 6749 to implement CSRF.  But
    /// it only says, "Should utilize the "state" request parameter to deliver this value"
    ///
    /// During a redirect response, if a "errorId" parameter is present and the client exists
    /// as a <see cref="UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME"/> client then
    /// transform the default Duende error response which would have redirected the client
    /// to a Duende error page to what is expected according to RFC 6749.  The redirect,
    /// is the clients original redirect url and params are error and error_description
    ///
    /// </summary>
    /// <param name="context"></param>
    /// <param name="clients"></param>
    /// <param name="udapServerOptions"></param>
    /// <param name="interactionService"></param>
    /// <returns></returns>
    public async Task Invoke(
        HttpContext context,
        IClientStore clients,
        ServerSettings udapServerOptions,
        IIdentityServerInteractionService interactionService)
    {
        if (context.Request.Path.Value != null &&
            context.Request.Path.Value.Contains(Constants.ProtocolRoutePaths.Authorize))
        {
            var requestParams = context.Request.Query;
           
            if (requestParams.Any())
            {
                if (udapServerOptions.ForceStateParamOnAuthorizationCode)
                {
                    if (!requestParams.TryGetValue(AuthorizeRequest.State, out var state))
                    {
                        var client =
                            await clients.FindClientByIdAsync(
                                requestParams.AsNameValueCollection().Get(AuthorizeRequest.ClientId));

                        if (client != null &&
                            client.ClientSecrets.Any(cs =>
                                cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME))
                        {
                            await RenderMissingStateErrorResponse(context);
                            _logger.LogInformation($"{nameof(UdapAuthorizationResponseMiddleware)} executed");
                            return;
                        }
                    }
                }
            }

            context.Response.OnStarting(async () =>
            {
                if (context.Response.StatusCode == (int)HttpStatusCode.Redirect &&
                    !context.Response.Headers.Location.IsNullOrEmpty()
                   )
                {
                    var uri = new Uri(context.Response.Headers.Location!);
                    var query = uri.Query;
                    var responseParams = QueryHelpers.ParseQuery(query);


                    if (responseParams.TryGetValue(_options.UserInteraction.ErrorIdParameter, out var errorId))
                    {
                        var requestParamCollection = context.Request.Query.AsNameValueCollection();
                        var client =
                            await clients.FindClientByIdAsync(
                                requestParamCollection.Get(AuthorizeRequest.ClientId));
                        var scope = requestParamCollection.Get(AuthorizeRequest.Scope);

                        if (client == null)
                        {
                            await RenderErrorResponse(context, interactionService, errorId);
                            return;
                        }

                        if (client != null &&
                            client.ClientSecrets.Any(cs =>
                                cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME))
                        {
                            await RenderErrorResponse(context, interactionService, errorId);
                            return;
                        }
                    }
                }

                _logger.LogTrace($"Why am I here: {string.Join(':', requestParams)}");
            });
        }

        await _next(context);
    }

    private Task RenderMissingStateErrorResponse(HttpContext context)
    {
        if (context.Request.Query.TryGetValue(
                AuthorizeRequest.RedirectUri,
                out StringValues redirectUri))
        {
            var url = BuildRedirectUrl(
                context, 
                redirectUri,
                AuthorizeErrors.InvalidRequest, 
                "Missing state");

            context.Response.Redirect(url);
        }

        return Task.CompletedTask;
    }

    private async Task RenderErrorResponse(
        HttpContext context,
        IIdentityServerInteractionService interactionService,
        StringValues errorId)
    {
        var errorMessage = await interactionService.GetErrorContextAsync(errorId);

        if (errorMessage.Error == AuthorizeErrors.UnsupportedResponseType)
        {
            //
            // Include error in redirect
            //

            if (context.Request.Query.TryGetValue(
                    AuthorizeRequest.RedirectUri,
                    out StringValues redirectUri))
            {
                var url = BuildRedirectUrl(
                    context, 
                    redirectUri, 
                    AuthorizeErrors.InvalidRequest,
                    errorMessage.ErrorDescription);

                context.Response.Redirect(url);
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

    private static string BuildRedirectUrl(
        HttpContext context, 
        StringValues redirectUri,
        string error,
        string errorDescription)
    {
        var sb = new StringBuilder();

        sb.Append(redirectUri).Append("?");

        sb.Append(AuthorizeResponse.Error)
            .Append("=")
            // Transform error of unsupported_response_type to invalid_request
            // Seems reasonable if you read RFC 6749
            // TODO: PR to Duende?
            .Append(error);

        sb.Append("&")
            .Append(AuthorizeResponse.ErrorDescription)
            .Append("=")
            .Append(errorDescription);

        if (context.Request.Query.TryGetValue(
                AuthorizeRequest.ResponseType,
                out StringValues responseType))
        {
            sb.Append("&")
                .Append(AuthorizeRequest.ResponseType)
                .Append("=")
                .Append(responseType);
        }

        if (context.Request.Query.TryGetValue(
                AuthorizeRequest.Scope,
                out StringValues scope))
        {
            sb.Append("&")
                .Append(AuthorizeRequest.Scope)
                .Append("=")
                .Append(scope);
        }

        if (context.Request.Query.TryGetValue(
                AuthorizeRequest.State,
                out StringValues state))
        {
            sb.Append("&")
                .Append(AuthorizeRequest.State)
                .Append("=")
                .Append(state);
        }

        if (context.Request.Query.TryGetValue(
                AuthorizeRequest.Nonce,
                out StringValues nonce))
        {
            sb.Append("&")
                .Append(AuthorizeRequest.Nonce)
                .Append("=")
                .Append(nonce);
        }

        return sb.ToString();
    }
}
