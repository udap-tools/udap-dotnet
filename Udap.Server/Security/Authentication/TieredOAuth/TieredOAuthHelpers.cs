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
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Udap.Client.Client;
using Udap.Model;

namespace Udap.Server.Security.Authentication.TieredOAuth;
public static class TieredOAuthHelpers
{
    public static async Task<AuthenticationProperties> BuildDynamicTieredOAuthOptions(
        IIdentityServerInteractionService interactionService,
        IUdapClient udapClient,
        string scheme, 
        string redirectUri,
        string returnUrl)
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

        var parts = idp.Split(new[] { '?' }, StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length > 1)
        {
            props.Parameters.Add(UdapConstants.Community, parts[1]);
        }

        var idpUri = new Uri(idp);
        string idpBaseUrl;

        if (idp.Contains($":{idpUri.Port}"))
        {
            idpBaseUrl = $"{idpUri.Scheme}{Uri.SchemeDelimiter}{idpUri.Host}:{idpUri.Port}{idpUri.LocalPath}";
        }
        else
        {
            idpBaseUrl = $"{idpUri.Scheme}{Uri.SchemeDelimiter}{idpUri.Host}{idpUri.LocalPath}";
        }
       
        var request = new DiscoveryDocumentRequest
        {
            Address = idpBaseUrl,
            Policy = new IdentityModel.Client.DiscoveryPolicy()
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
}
