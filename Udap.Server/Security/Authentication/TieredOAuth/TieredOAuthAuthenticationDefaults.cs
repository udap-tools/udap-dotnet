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
}