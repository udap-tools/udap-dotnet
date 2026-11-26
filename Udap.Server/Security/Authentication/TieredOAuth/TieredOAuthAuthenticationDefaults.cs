#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authentication;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public static class TieredOAuthAuthenticationDefaults
{
    /// <summary>
    /// Default value for <see cref="Microsoft.AspNetCore.Authentication.AuthenticationScheme.Name"/>.
    /// </summary>
    public const string AuthenticationScheme = "TieredOAuth";

    /// <summary>
    /// Default value for <see cref="Microsoft.AspNetCore.Authentication.AuthenticationScheme.DisplayName"/>.
    /// </summary>
    public static readonly string DisplayName = "Launch Tiered OAuth";

    public static readonly string CallbackPath = "/federation/udap-tiered/signin";

    /// <summary>
    /// Configuration section <c>AddTieredOAuth</c> reads <see cref="TieredOAuthAuthenticationOptions.CallbackBaseUrl"/>
    /// and <see cref="TieredOAuthAuthenticationOptions.AllowedIdPs"/> from.
    /// </summary>
    public const string ConfigurationSection = "TieredOAuth";

    /// <summary>
    /// <see cref="AuthenticationProperties.Items"/> key holding the <c>iss</c> of the upstream IdP's validated
    /// id_token. Hosts link local accounts on this issuer plus <c>sub</c>, because every upstream IdP shares
    /// the one Tiered OAuth scheme name.
    /// </summary>
    public const string IdPIssuerItem = "udap_tiered_idp_iss";

    /// <summary>
    /// The external login provider key for a Tiered OAuth user: the scheme name and the upstream IdP's issuer,
    /// e.g. <c>TieredOAuth|https://idp.example.com</c>. Two IdPs that issue the same <c>sub</c> get different keys.
    /// </summary>
    public static string ExternalProviderKey(string scheme, string issuer) => $"{scheme}|{issuer}";
}