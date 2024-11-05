﻿#region (c) 2023 Joseph Shook. All rights reserved.
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
using Udap.Model;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public class TieredOAuthAuthenticationOptions : OAuthOptions
{

    private readonly JwtSecurityTokenHandler _defaultHandler = new JwtSecurityTokenHandler();

    /// <inheritdoc />

    public TieredOAuthAuthenticationOptions()
    {
        SignInScheme = TieredOAuthAuthenticationDefaults.AuthenticationScheme;

        // TODO:  configurable for the non-dynamic AddTieredOAuthForTests call. 
        Scope.Add(UdapConstants.StandardScopes.Udap);
        Scope.Add(OidcConstants.StandardScopes.OpenId);
        Scope.Add(OidcConstants.StandardScopes.Email);
        Scope.Add(OidcConstants.StandardScopes.Profile);

        SecurityTokenValidator = _defaultHandler;

        //
        // Properties below are required to survive Microsoft.AspNetCore.Authentication.RemoteAuthenticationOptions.Validate(String scheme)
        //
        // AuthorizationEndpoint and TokenEndpoint are placed them in the AuthenticationProperties.Parameters
        // and set during the GET /externallogin/challenge
        //
        // ClientSecret is not used
        // ClientId is set after dynamic registration
        //
        AuthorizationEndpoint = "/connect/authorize";
        TokenEndpoint = "/connect/token";
        ClientSecret = "signed metadata";
        ClientId = "temporary";
        CallbackPath = TieredOAuthAuthenticationDefaults.CallbackPath;
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
    
}