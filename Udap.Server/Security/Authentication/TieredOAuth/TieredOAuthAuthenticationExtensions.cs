#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client.Client;
using Udap.Client.Configuration;

namespace Udap.Server.Security.Authentication.TieredOAuth;
public static class TieredOAuthAuthenticationExtensions
{


    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuth([NotNull] this AuthenticationBuilder builder)
    {
        return builder.AddTieredOAuth(TieredOAuthAuthenticationDefaults.AuthenticationScheme, options => { });
    }

    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configuration">The delegate used to configure the Tiered OAuth options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuth(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] Action<TieredOAuthAuthenticationOptions> configuration)
    {
        return builder.AddTieredOAuth(TieredOAuthAuthenticationDefaults.AuthenticationScheme, configuration);
    }

    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the Tiered OAuth options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuth(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] string scheme,
        [NotNull] Action<TieredOAuthAuthenticationOptions> configuration)
    {
        return builder.AddTieredOAuth(scheme, TieredOAuthAuthenticationDefaults.DisplayName, configuration);
    }

    /// <summary>
    /// Adds <see cref="TieredOAuthAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Tiered OAuth authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="caption">The optional display name associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the Tiered OAuth options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddTieredOAuth(
        this AuthenticationBuilder builder, 
        string scheme,
        string caption,
        Action<TieredOAuthAuthenticationOptions> configuration)
    {

        builder.Services.TryAddTransient<HeaderAugmentationHandler>();
        builder.Services.AddHttpClient<IUdapClient, UdapClient>().AddHttpMessageHandler<HeaderAugmentationHandler>();
        
        builder.Services.TryAddSingleton<UdapClientMessageHandler>(sp =>
            {
                var handler = new UdapClientMessageHandler(
                    sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                    sp.GetRequiredService<ILogger<UdapClient>>());

                handler.InnerHandler = sp.GetRequiredService<HeaderAugmentationHandler>();

                return handler;
            });
        
        builder.Services.TryAddSingleton<IPostConfigureOptions<TieredOAuthAuthenticationOptions>, TieredOAuthPostConfigureOptions>();
        return builder.AddOAuth<TieredOAuthAuthenticationOptions, TieredOAuthAuthenticationHandler>(scheme, caption, configuration);
    }
}