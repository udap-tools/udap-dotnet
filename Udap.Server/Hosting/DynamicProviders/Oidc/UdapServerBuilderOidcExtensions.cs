#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Model;
using Udap.Server.Security.Authentication.TieredOAuth;

namespace Udap.Server.Hosting.DynamicProviders.Oidc;
public static class UdapServerBuilderOidcExtensions
{

    /// <summary>Adds the OIDC dynamic provider feature build specifically for UDAP Tiered OAuth.</summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static IUdapServiceBuilder AddTieredOAuthDynamicProvider(this IUdapServiceBuilder builder)
    {
        builder.Services.Configure<IdentityServerOptions>(options =>
        {
            // this associates the TieredOAuthAuthenticationHandler and options (TieredOAuthAuthenticationOptions) classes
            // to the idp class (OidcProvider) and type value ("udap_oidc") from the identity provider store
            options.DynamicProviders.AddProviderType<TieredOAuthAuthenticationHandler, TieredOAuthAuthenticationOptions, OidcProvider>("udap_oidc");
        });





        // this registers the OidcConfigureOptions to build the TieredOAuthAuthenticationOptions from the OidcProvider data
        builder.Services.AddSingleton<IConfigureOptions<TieredOAuthAuthenticationOptions>, UdapOidcConfigureOptions>();

        // this services from ASP.NET Core and are added manually since we're not using the 
        // AddOpenIdConnect helper that we'd normally use statically on the AddAuthentication.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TieredOAuthAuthenticationOptions>, TieredOAuthPostConfigureOptions>());
        builder.Services.TryAddTransient<TieredOAuthAuthenticationHandler>();





        builder.Services.TryAddTransient<HeaderAugmentationHandler>();
        builder.Services.AddHttpClient<IUdapClient, UdapClient>().AddHttpMessageHandler<HeaderAugmentationHandler>();

        builder.Services.TryAddSingleton<UdapClientDiscoveryValidator>();
        builder.Services.TryAddSingleton<UdapClientMessageHandler>();


        builder.Services.TryAddSingleton<UdapClientMessageHandler>(sp =>
        {
            var handler = new UdapClientMessageHandler(
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<ILogger<UdapClient>>());

            handler.InnerHandler = sp.GetRequiredService<HeaderAugmentationHandler>();

            return handler;
        });

        return builder;
    }
}
