#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace Udap.Server.Security.Authentication.TieredOAuth;

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