#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Options;
using Udap.Server.Configuration;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public class TieredIdpServerSettings : IPostConfigureOptions<ServerSettings>
{
    /// <summary>
    /// Invoked to configure a <typeparamref name="TOptions" /> instance.
    /// </summary>
    /// <param name="name">The name of the options instance being configured.</param>
    /// <param name="options">The options instance to configured.</param>
    public void PostConfigure(string? name, ServerSettings options)
    {
        options.TieredIdp = true;
    }
}