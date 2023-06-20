using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Duende.IdentityServer;
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

public class TieredOAuthAuthenticationOptions : OAuthOptions{

    public TieredOAuthAuthenticationOptions()
    {
        CallbackPath = TieredOAuthAuthenticationDefaults.CallbackPath;
        ClientId = "dynamic";
        ClientSecret = "signed metadata";
        AuthorizationEndpoint = TieredOAuthAuthenticationDefaults.AuthorizationEndpoint;
        TokenEndpoint = TieredOAuthAuthenticationDefaults.TokenEndpoint;
        SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
    }
}

public static class TieredOAuthAuthenticationDefaults
{
    /// <summary>
    /// Default value for <see cref="AuthenticationScheme.Name"/>.
    /// </summary>
    public const string AuthenticationScheme = "TieredOAuth";

    /// <summary>
    /// Default value for <see cref="AuthenticationScheme.DisplayName"/>.
    /// </summary>
    public static readonly string DisplayName = "UDAP Tiered OAuth";

    public static readonly string CallbackPath = "/signin-tieredoauth";

    public static readonly string AuthorizationEndpoint = "https://localhost:5001/connect/authorize";

    public static readonly string TokenEndpoint = "https://localhost:5001/connect/token";
}