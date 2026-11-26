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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Server.Configuration;
using Udap.Server.Hosting;

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
        // The idp comes from an anonymous request, and discovery names the registration, token and JWKS endpoints, so
        // every connection this client makes refuses non-public addresses unless OutboundConnectionOptions allows them.
        builder.Services.AddUdapOutboundConnectionOptions();
        builder.Services.AddHttpClient<IUdapClient, UdapClient>()
            .ConfigurePrimaryHttpMessageHandler(sp => OutboundConnectGuard.CreateHandler(
                sp.GetRequiredService<IOptions<OutboundConnectionOptions>>().Value,
                sp.GetService<IHostEnvironment>()))
            .AddHttpMessageHandler<HeaderAugmentationHandler>();
        
        builder.Services.TryAddSingleton<UdapClientMessageHandler>(sp =>
            {
                var handler = new UdapClientMessageHandler(
                    sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                    sp.GetRequiredService<ILogger<UdapClient>>())
                {
                    InnerHandler = sp.GetRequiredService<HeaderAugmentationHandler>()
                };

                return handler;
            });
        
        builder.Services.TryAddSingleton<IPostConfigureOptions<TieredOAuthAuthenticationOptions>, TieredOAuthPostConfigureOptions>();

        // Registered before the code's configure action, so a value set in code wins over configuration, and
        // configuration wins over the UdapIdpBaseUrl default applied in post-configure.
        builder.Services.AddOptions<TieredOAuthAuthenticationOptions>(scheme)
            .Configure<IServiceProvider>((options, services) =>
                BindConfiguration(options, services.GetService<IConfiguration>()));

        return builder.AddOAuth<TieredOAuthAuthenticationOptions, TieredOAuthAuthenticationHandler>(scheme, caption, configuration);
    }

    /// <summary>
    /// Reads <see cref="TieredOAuthAuthenticationOptions.CallbackBaseUrl"/> and
    /// <see cref="TieredOAuthAuthenticationOptions.AllowedIdPs"/> from the
    /// <see cref="TieredOAuthAuthenticationDefaults.ConfigurationSection"/> section, e.g.
    /// <code>
    /// "TieredOAuth": {
    ///   "CallbackBaseUrl": "https://auth.example.com",
    ///   "AllowedIdPs": [ "https://idp.example.com" ]
    /// }
    /// </code>
    /// or the environment variable <c>TieredOAuth__CallbackBaseUrl</c>.
    /// </summary>
    private static void BindConfiguration(TieredOAuthAuthenticationOptions options, IConfiguration? configuration)
    {
        var section = configuration?.GetSection(TieredOAuthAuthenticationDefaults.ConfigurationSection);

        if (section == null)
        {
            return;
        }

        var callbackBaseUrl = section[nameof(TieredOAuthAuthenticationOptions.CallbackBaseUrl)];
        if (!string.IsNullOrWhiteSpace(callbackBaseUrl))
        {
            options.CallbackBaseUrl = callbackBaseUrl;
        }

        var allowedIdPs = section.GetSection(nameof(TieredOAuthAuthenticationOptions.AllowedIdPs))
            .GetChildren()
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!)
            .ToList();

        if (allowedIdPs.Count > 0)
        {
            options.AllowedIdPs = allowedIdPs;
        }
    }
}