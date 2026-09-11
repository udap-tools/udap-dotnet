#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Specialized;
using System.Net;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Udap.Model;
using Udap.Server.Configuration;
using Udap.Server.Extensions;
using Udap.Server.Storage;
using Udap.Util.Extensions;
using static Duende.IdentityModel.OidcConstants;

namespace Udap.Server.Hosting;


/// <summary>
/// Identity Server by default responds with a redirect to /home/error/errorid=...
/// for all errors in response to failed /connect/authorize? requests.
///
/// UDAP is expecting 400-599 errors and or redirects to redirect_uri
/// with an error and error_description in the query params.
///
/// Require state parameter from clients by configuring the
/// <see cref="ServerSettings.ForceStateParamOnAuthorizationCode"/> to true.
///
/// The authorization request may arrive as GET (query string) or POST
/// (application/x-www-form-urlencoded body); both are read into one parameter
/// collection so every check and error redirect behaves the same way.
/// </summary>
internal class UdapAuthorizationResponseMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IdentityServerOptions _options;
    private readonly ILogger<UdapAuthorizationResponseMiddleware> _logger;

    public UdapAuthorizationResponseMiddleware(
        RequestDelegate next,
        IdentityServerOptions options,
        ILogger<UdapAuthorizationResponseMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// During a Server request to "/authorize", while Server is configured for
    /// <see cref="ServerSettings.ForceStateParamOnAuthorizationCode"/>, and the
    /// state parameter is missing and client has a <see cref="Duende.IdentityServer.Models.Secret"/>
    /// of type  <see cref="UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME"/> then return
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
            var requestParams = await ReadRequestParametersAsync(context);

            if (requestParams.Count != 0)
            {
                // Check if state is required:
                // 1. Explicit config (ForceStateParamOnAuthorizationCode)
                // 2. Server only supports V2 (EffectiveForceState)
                // 3. Client is a V2 client (based on stored property)
                if (requestParams.Get(AuthorizeRequest.State) == null)
                {
                    var client =
                        await clients.FindClientByIdAsync(
                            requestParams.Get(AuthorizeRequest.ClientId) ?? string.Empty,
                            context.RequestAborted);

                    if (client != null &&
                        client.ClientSecrets.Any(cs =>
                            cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME))
                    {
                        var requireState = udapServerOptions.EffectiveForceState;

                        if (requireState)
                        {
                            RenderMissingStateErrorResponse(context, requestParams);
                            _logger.LogInformation("{Middleware} rejected an authorization request with no state", nameof(UdapAuthorizationResponseMiddleware));

                            return;
                        }
                    }
                }

                //
                // During Tiered OAuth from data holder to IdP the udap and idp scopes are required 
                // https://hl7.org/fhir/us/udap-security/user.html#data-holder-authentication-request-to-idp
                //
                if (udapServerOptions.TieredIdp)
                {
                    var client =
                        await clients.FindClientByIdAsync(
                            requestParams.Get(AuthorizeRequest.ClientId) ?? string.Empty,
                            context.RequestAborted);
                    var scope = requestParams.Get(AuthorizeRequest.Scope);
                    
                    var scopes = scope?.FromSpaceSeparatedString();
                    var udap = (scopes ?? Array.Empty<string>()).FirstOrDefault(s => s == "udap");
                    var openid = (scopes ?? Array.Empty<string>()).FirstOrDefault(s => s == "openid");

                    if (client != null &&
                        client.ClientSecrets.Any(cs =>
                            cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME))
                    {
                        if (string.IsNullOrEmpty(udap) || string.IsNullOrEmpty(openid))
                        {
                            RenderRequiredScopeErrorResponse(context, requestParams);
                            _logger.LogInformation("{Middleware} rejected a tiered OAuth request missing the udap or openid scope", nameof(UdapAuthorizationResponseMiddleware));

                            return;
                        }
                    }
                }
            }

            context.Response.OnStarting(async () =>
            {
                // Duende v8 issues HTTP 303 (See Other) for authorization endpoint
                // redirects (FAPI 2.0); 302 kept for any remaining legacy paths.
                if ((context.Response.StatusCode == (int)HttpStatusCode.Redirect ||
                     context.Response.StatusCode == (int)HttpStatusCode.SeeOther) &&
                    !StringValues.IsNullOrEmpty(context.Response.Headers.Location)
                   )
                {
                    var uri = new Uri(context.Response.Headers.Location!);
                    var query = uri.Query;
                    var responseParams = QueryHelpers.ParseQuery(query);


                    if (responseParams.TryGetValue(_options.UserInteraction.ErrorIdParameter, out var errorId))
                    {
                        var clientId = requestParams.Get(AuthorizeRequest.ClientId);
                        Duende.IdentityServer.Models.Client? client = null;

                        if(clientId != null){
                            client = await clients.FindClientByIdAsync(clientId, context.RequestAborted);
                        }

                        if (client == null)
                        {
                            await RenderErrorResponse(context, interactionService, errorId, requestParams);
                            return;
                        }

                        if (client.ClientSecrets.Any(cs =>
                                cs.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME))
                        {
                            await RenderErrorResponse(context, interactionService, errorId, requestParams);
                        }
                    }
                }
            });
        }

        await _next(context);
    }

    /// <summary>
    /// Reads the authorization request parameters from the form body for a POST or
    /// from the query string otherwise. <see cref="HttpRequest.ReadFormAsync(CancellationToken)"/>
    /// caches the parsed form on the request, so the authorize endpoint downstream
    /// sees the same values.
    /// </summary>
    private static async Task<NameValueCollection> ReadRequestParametersAsync(HttpContext context)
    {
        IEnumerable<KeyValuePair<string, StringValues>> source;

        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasApplicationFormContentType())
        {
            source = await context.Request.ReadFormAsync(context.RequestAborted);
        }
        else
        {
            source = context.Request.Query;
        }

        var parameters = new NameValueCollection();

        foreach (var (key, values) in source)
        {
            foreach (var value in values)
            {
                parameters.Add(key, value);
            }
        }

        return parameters;
    }

    private static void RenderRequiredScopeErrorResponse(HttpContext context, NameValueCollection requestParams)
    {
        var redirectUri = requestParams.Get(AuthorizeRequest.RedirectUri);

        if (redirectUri != null)
        {
            var url = BuildRedirectUrl(
                requestParams,
                redirectUri,
                AuthorizeErrors.InvalidRequest,
                "Missing udap and/or openid scope between data holder and IdP");

            context.Response.Redirect(url);
        }
    }

    private static void RenderMissingStateErrorResponse(HttpContext context, NameValueCollection requestParams)
    {
        var redirectUri = requestParams.Get(AuthorizeRequest.RedirectUri);

        if (redirectUri != null)
        {
            var url = BuildRedirectUrl(
                requestParams,
                redirectUri,
                AuthorizeErrors.InvalidRequest,
                "Missing state");

            context.Response.Redirect(url);
        }
    }

    private static async Task RenderErrorResponse(
        HttpContext context,
        IIdentityServerInteractionService interactionService,
        StringValues errorId,
        NameValueCollection requestParams)
    {
        var errorMessage = await interactionService.GetErrorContextAsync(errorId, context.RequestAborted);

        if (errorMessage?.Error == AuthorizeErrors.UnsupportedResponseType
            || errorMessage is { Error: AuthorizeErrors.InvalidRequest, ErrorDescription: "Missing response_type" }
            )
        {
            //
            // Include error in redirect
            //
            var redirectUri = requestParams.Get(AuthorizeRequest.RedirectUri);

            if (redirectUri != null)
            {
                var url = BuildRedirectUrl(
                    requestParams,
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

    /// <summary>
    /// Builds the RFC 6749 error redirect. Values are URL-encoded and appended with
    /// <see cref="QueryHelpers.AddQueryString(string, IEnumerable{KeyValuePair{string, string?}})"/>
    /// so a redirect_uri that already carries a query string stays valid.
    /// </summary>
    private static string BuildRedirectUrl(
        NameValueCollection requestParams,
        string redirectUri,
        string error,
        string? errorDescription)
    {
        var parameters = new List<KeyValuePair<string, string?>>
        {
            // Transform error of unsupported_response_type to invalid_request
            // Seems reasonable if you read RFC 6749
            // TODO: PR to Duende?
            new(AuthorizeResponse.Error, error)
        };

        if (errorDescription != null)
        {
            parameters.Add(new KeyValuePair<string, string?>(AuthorizeResponse.ErrorDescription, errorDescription));
        }

        foreach (var name in new[]
                 {
                     AuthorizeRequest.ResponseType,
                     AuthorizeRequest.Scope,
                     AuthorizeRequest.State,
                     AuthorizeRequest.Nonce
                 })
        {
            var value = requestParams.Get(name);

            if (value != null)
            {
                parameters.Add(new KeyValuePair<string, string?>(name, value));
            }
        }

        return QueryHelpers.AddQueryString(redirectUri, parameters);
    }
}
