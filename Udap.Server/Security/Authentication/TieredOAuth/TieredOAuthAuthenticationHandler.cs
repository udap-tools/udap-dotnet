#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public class TieredOAuthAuthenticationHandler : OAuthHandler<TieredOAuthAuthenticationOptions>
{
    /// <summary>
    /// Initializes a new instance of <see cref="TieredOAuthHandler" />.
    /// </summary>
    /// <inheritdoc />
    public TieredOAuthAuthenticationHandler(IOptionsMonitor<TieredOAuthAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : 
        base(options, logger, encoder, clock)
    {
    }

    /// <summary>Constructs the OAuth challenge url.</summary>
    /// <param name="properties">The <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationProperties" />.</param>
    /// <param name="redirectUri">The url to redirect to once the challenge is completed.</param>
    /// <returns>The challenge url.</returns>
    protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
    {
        return base.BuildChallengeUrl(properties, redirectUri);
    }
}