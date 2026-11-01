#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Udap.UI.Options;
using Udap.UI.Services;

// ReSharper disable once CheckNamespace
namespace Udap.UI;

public static class UdapUIServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Udap.UI interaction services (<see cref="IUdapLoginService"/>,
    /// <see cref="IUdapExternalLoginService"/>, <see cref="IUdapLogoutService"/>,
    /// <see cref="IUdapConsentService"/>) and the default <see cref="IUdapUserStore"/>.
    /// Hosts building their own login, consent and logout pages call these services; the
    /// built-in Udap.UI pages use them too.
    /// </summary>
    /// <remarks>
    /// Registrations use TryAdd: a host's own <see cref="IUdapUserStore"/> (or any of these services)
    /// registered before this call is kept, and one registered after it wins at resolution.
    /// </remarks>
    public static IServiceCollection AddUdapUI(this IServiceCollection services, Action<UdapUIOptions>? configure = null)
    {
        services.AddOptions<UdapUIOptions>();

        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddTransient<IUdapUserStore, TestUserStoreAdapter>();
        services.TryAddTransient<IUdapLoginService, UdapLoginService>();
        services.TryAddTransient<IUdapExternalLoginService, UdapExternalLoginService>();
        services.TryAddTransient<IUdapLogoutService, UdapLogoutService>();
        services.TryAddTransient<IUdapConsentService, UdapConsentService>();

        return services;
    }
}
