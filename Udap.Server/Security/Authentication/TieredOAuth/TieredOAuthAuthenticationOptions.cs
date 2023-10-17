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
using IdentityModel;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public class TieredOAuthAuthenticationOptions : OAuthOptions
{

    private readonly JwtSecurityTokenHandler _defaultHandler = new JwtSecurityTokenHandler();

    public TieredOAuthAuthenticationOptions()
    {
        CallbackPath = TieredOAuthAuthenticationDefaults.CallbackPath;
        ClientId = "dynamic";
        ClientSecret = "signed metadata";
        // AuthorizationEndpoint = TieredOAuthAuthenticationDefaults.AuthorizationEndpoint;
        // TokenEndpoint = TieredOAuthAuthenticationDefaults.TokenEndpoint;
        SignInScheme = TieredOAuthAuthenticationDefaults.AuthenticationScheme;

        // TODO:  configurable for the non-dynamic AddTieredOAuthForTests call. 
        Scope.Add(OidcConstants.StandardScopes.OpenId);
        // Scope.Add(UdapConstants.StandardScopes.FhirUser);
        Scope.Add(OidcConstants.StandardScopes.Email);
        Scope.Add(OidcConstants.StandardScopes.Profile);

        SecurityTokenValidator = _defaultHandler;

        //
        // Defaults to survive the IIdentityProviderConfigurationValidator
        // All of these are set during the GET /externallogin/challenge by
        // placing them in the AuthenticationProperties.Parameters
        //
        AuthorizationEndpoint = "/connect/authorize";
        TokenEndpoint = "/connect/token";
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

    public string Community { get; set; }
}