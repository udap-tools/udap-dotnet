#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;

namespace Udap.UI.Services;

/// <summary>
/// Lets the built-in Udap.UI pages work in hosts that never called
/// <see cref="UdapUIServiceCollectionExtensions.AddUdapUI"/>: a registered service is used when present,
/// otherwise the default implementation is created on the fly.
/// </summary>
internal static class UdapUIServiceResolver
{
    public static IUdapUserStore GetUdapUserStore(this IServiceProvider services)
        => services.GetService<IUdapUserStore>() ?? ActivatorUtilities.CreateInstance<TestUserStoreAdapter>(services);

    public static IUdapLoginService GetUdapLoginService(this IServiceProvider services)
        => services.GetService<IUdapLoginService>()
           ?? ActivatorUtilities.CreateInstance<UdapLoginService>(services, services.GetUdapUserStore());

    public static IUdapExternalLoginService GetUdapExternalLoginService(this IServiceProvider services)
        => services.GetService<IUdapExternalLoginService>()
           ?? ActivatorUtilities.CreateInstance<UdapExternalLoginService>(services, services.GetUdapUserStore());

    public static IUdapLogoutService GetUdapLogoutService(this IServiceProvider services)
        => services.GetService<IUdapLogoutService>() ?? ActivatorUtilities.CreateInstance<UdapLogoutService>(services);

    public static IUdapConsentService GetUdapConsentService(this IServiceProvider services)
        => services.GetService<IUdapConsentService>() ?? ActivatorUtilities.CreateInstance<UdapConsentService>(services);
}
