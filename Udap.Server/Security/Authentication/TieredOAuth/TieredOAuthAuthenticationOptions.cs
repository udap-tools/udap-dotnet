#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public class TieredOAuthAuthenticationOptions : OAuthOptions{

    private readonly JwtSecurityTokenHandler _defaultHandler = new JwtSecurityTokenHandler();

    public TieredOAuthAuthenticationOptions()
    {
        CallbackPath = TieredOAuthAuthenticationDefaults.CallbackPath;
        ClientId = "dynamic";
        ClientSecret = "signed metadata";
        // AuthorizationEndpoint = TieredOAuthAuthenticationDefaults.AuthorizationEndpoint;
        // TokenEndpoint = TieredOAuthAuthenticationDefaults.TokenEndpoint;
        SignInScheme = TieredOAuthAuthenticationDefaults.AuthenticationScheme;
        
        // DCR at Tiered OAuth only is asking for these two. 
        Scope.Add("openid");
        Scope.Add("fhirUser");
        // Scope.Add("email");
        // Scope.Add("profile");

        SecurityTokenValidator = _defaultHandler;
    }

    /// <summary>
    /// Gets or sets the <see cref="ISecurityTokenValidator"/> used to validate identity tokens.
    /// </summary>
    public ISecurityTokenValidator SecurityTokenValidator { get; set; }

    /// <summary>
    /// Gets or sets the parameters used to validate identity tokens.
    /// </summary>
    /// <remarks>Contains the types and definitions required for validating a token.</remarks>
    public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

    /// <summary>
    /// The IdP’s base URL is the URL listed in the iss claim of ID tokens issued by the IdP as detailed in
    /// Section 2 of the OpenID Connect Core 1.0 specification (OIDC Core)
    /// <see cref="http://hl7.org/fhir/us/udap-security/user.html#client-authorization-request-to-data-holder"/>
    /// </summary>
    public string IdPBaseUrl { get; set; }
}