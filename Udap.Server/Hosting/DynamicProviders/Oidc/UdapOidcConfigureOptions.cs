#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Hosting.DynamicProviders;
using Duende.IdentityServer.Models;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Udap.Server.Security.Authentication.TieredOAuth;

namespace Udap.Server.Hosting.DynamicProviders.Oidc;
public class UdapOidcConfigureOptions : ConfigureAuthenticationOptions<TieredOAuthAuthenticationOptions, OidcProvider>
{
    /// <summary>
    /// Allows for configuring the handler options from the identity provider configuration.
    /// </summary>
    /// <param name="context"></param>
    public UdapOidcConfigureOptions(IHttpContextAccessor httpContextAccessor, ILogger<UdapOidcConfigureOptions> logger) : base(httpContextAccessor, logger)
    {
    }

    protected override void Configure(ConfigureAuthenticationContext<TieredOAuthAuthenticationOptions, OidcProvider> context)
    {
        context.AuthenticationOptions.SignInScheme = context.DynamicProviderOptions.SignInScheme;
        // context.AuthenticationOptions.SignOutScheme = context.DynamicProviderOptions.SignOutScheme;

        // context.AuthenticationOptions.Authority = context.IdentityProvider.Authority;

        //
        // When this is the first time the idp is contacted then this property will be empty until it is dynamically
        // registered and placed in the Provider table.
        // The razor page that calls the HttpContext.ChallengeAsync method adds the authorization endpoint
        // when it request the idp servers OpenId configuration.
        //
        context.AuthenticationOptions.AuthorizationEndpoint = context.IdentityProvider.Authority == "template" ? string.Empty : context.IdentityProvider.Authority;
        
        // context.AuthenticationOptions.RequireHttpsMetadata = context.IdentityProvider.Authority.StartsWith("https");

        context.AuthenticationOptions.ClientId = context.IdentityProvider.ClientId;
        context.AuthenticationOptions.ClientSecret = context.IdentityProvider.ClientSecret;

        // context.AuthenticationOptions.ResponseType = context.IdentityProvider.ResponseType;
        // context.AuthenticationOptions.ResponseMode =
        //     context.IdentityProvider.ResponseType.Contains("id_token") ? "form_post" : "query";
        
        context.AuthenticationOptions.UsePkce = context.IdentityProvider.UsePkce;

        context.AuthenticationOptions.Scope.Clear();
        foreach (var scope in context.IdentityProvider.Scopes)
        {
            context.AuthenticationOptions.Scope.Add(scope);
        }

        context.AuthenticationOptions.SaveTokens = true;
        // context.AuthenticationOptions.GetClaimsFromUserInfoEndpoint = context.IdentityProvider.GetClaimsFromUserInfoEndpoint;
        // context.AuthenticationOptions.DisableTelemetry = true;
#if NET5_0_OR_GREATER
        // context.AuthenticationOptions.MapInboundClaims = false;
#else
            context.AuthenticationOptions.SecurityTokenValidator = new JwtSecurityTokenHandler 
            {
                MapInboundClaims = false
            };
#endif
        context.AuthenticationOptions.TokenValidationParameters.NameClaimType = JwtClaimTypes.Name;
        context.AuthenticationOptions.TokenValidationParameters.RoleClaimType = JwtClaimTypes.Role;

        context.AuthenticationOptions.CallbackPath = context.PathPrefix + "/signin";
        // context.AuthenticationOptions.SignedOutCallbackPath = context.PathPrefix + "/signout-callback";
        // context.AuthenticationOptions.RemoteSignOutPath = context.PathPrefix + "/signout";
    }
}
