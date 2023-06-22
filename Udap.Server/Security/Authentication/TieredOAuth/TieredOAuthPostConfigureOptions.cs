#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Options;
using Udap.Client.Client;

namespace Udap.Server.Security.Authentication.TieredOAuth;

public class TieredOAuthPostConfigureOptions : IPostConfigureOptions<TieredOAuthAuthenticationOptions>

{
    private readonly UdapClientMessageHandler _udapClientMessageHandler;

    /// <summary>
    /// Initializes a new instance of the <see cref="TieredOAuthPostConfigureOptions"/> class.
    /// </summary>
    /// <param name="udapClientMessageHandler"></param>
    public TieredOAuthPostConfigureOptions(UdapClientMessageHandler udapClientMessageHandler)
    {
        _udapClientMessageHandler = udapClientMessageHandler;
    }

    /// <summary>
    /// Invoked to configure a <typeparamref name="TieredOAuthAuthenticationOptions" /> instance.
    /// </summary>
    /// <param name="name">The name of the options instance being configured.</param>
    /// <param name="options">The options instance to configured.</param>
    public void PostConfigure(string? name, TieredOAuthAuthenticationOptions options)
    {
        options.BackchannelHttpHandler = _udapClientMessageHandler;
    }
}