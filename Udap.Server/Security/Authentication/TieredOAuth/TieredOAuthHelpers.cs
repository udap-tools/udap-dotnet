#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Web;
using Duende.IdentityServer.Services;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Udap.Client;
using Udap.Model;

namespace Udap.Server.Security.Authentication.TieredOAuth;
public static class TieredOAuthHelpers
{
    public static Task<AuthenticationProperties> BuildDynamicTieredOAuthOptions(
        IIdentityServerInteractionService interactionService,
        IUdapClient udapClient,
        string scheme,
        string redirectUri,
        string returnUrl)
    {
        return BuildDynamicTieredOAuthOptions(interactionService, udapClient, scheme, redirectUri, returnUrl, null);
    }

    /// <summary>
    /// Builds the challenge properties for a Tiered OAuth login, refusing an <c>idp</c> that
    /// <paramref name="options"/> does not allow (see <see cref="TieredOAuthAuthenticationOptions.AllowedIdPs"/>)
    /// before any request is sent to it.
    /// </summary>
    public static async Task<AuthenticationProperties> BuildDynamicTieredOAuthOptions(
        IIdentityServerInteractionService interactionService,
        IUdapClient udapClient,
        string scheme,
        string redirectUri,
        string returnUrl,
        TieredOAuthAuthenticationOptions? options)
    {
        if (interactionService.IsValidReturnUrl(returnUrl) == false)
        {
            throw new Exception("invalid return URL");
        }

        var props = new AuthenticationProperties
        {
            RedirectUri = redirectUri,

            Items =
            {
                { "returnUrl", returnUrl },
                { "scheme", scheme },
            }
        };

        
        var originalRequestParams = HttpUtility.ParseQueryString(returnUrl);
        var idp = (originalRequestParams.GetValues("idp") ?? throw new InvalidOperationException()).Last();

        var parts = idp.Split('?', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length > 1)
        {
            props.Parameters.Add(UdapConstants.Community, parts[1]);
        }

        // The idp comes from an anonymous request and this server is about to fetch from it.
        var idpUri = ValidateIdPUri(idp);
        string idpBaseUrl;

        if (idp.Contains($":{idpUri.Port}"))
        {
            idpBaseUrl = $"{idpUri.Scheme}{Uri.SchemeDelimiter}{idpUri.Host}:{idpUri.Port}{idpUri.LocalPath}";
        }
        else
        {
            idpBaseUrl = $"{idpUri.Scheme}{Uri.SchemeDelimiter}{idpUri.Host}{idpUri.LocalPath}";
        }

        if (options != null && !options.IsIdPAllowed(idpBaseUrl))
        {
            throw new InvalidOperationException($"IdP is not in AllowedIdPs: {idpBaseUrl}");
        }

        var request = new DiscoveryDocumentRequest
        {
            Address = idpBaseUrl,
            Policy = new Duende.IdentityModel.Client.DiscoveryPolicy()
            {
                EndpointValidationExcludeList = new List<string> { OidcConstants.Discovery.RegistrationEndpoint }
            }
        };

        var openIdConfig = await udapClient.ResolveOpenIdConfig(request);

        // TODO: Properties will be protected in state in the BuildChallengeUrl.  Need to trim out some of these
        // during the protect process.
        props.Parameters.Add(UdapConstants.Discovery.AuthorizationEndpoint, openIdConfig.AuthorizeEndpoint);
        props.Parameters.Add(UdapConstants.Discovery.TokenEndpoint, openIdConfig.TokenEndpoint);
        props.Parameters.Add("idpBaseUrl", idpBaseUrl.TrimEnd('/'));

        return props;
    }

    /// <summary>
    /// Parses the <c>idp</c> parameter and refuses anything this server should not send a request to: a relative
    /// URL, a URL with user info, or a scheme other than https (http is allowed only for a loopback host, as
    /// Duende's discovery policy allows).
    /// </summary>
    /// <exception cref="InvalidOperationException">The idp is not an acceptable URL.</exception>
    public static Uri ValidateIdPUri(string idp)
    {
        if (!Uri.TryCreate(idp, UriKind.Absolute, out var idpUri))
        {
            throw new InvalidOperationException("The idp parameter is not an absolute URL.");
        }

        if (!string.IsNullOrEmpty(idpUri.UserInfo))
        {
            throw new InvalidOperationException("The idp parameter must not contain user info.");
        }

        var isHttps = idpUri.Scheme == Uri.UriSchemeHttps;
        var isLoopbackHttp = idpUri.Scheme == Uri.UriSchemeHttp && idpUri.IsLoopback;

        if (!isHttps && !isLoopbackHttp)
        {
            throw new InvalidOperationException("The idp parameter must be an https URL.");
        }

        return idpUri;
    }
}
