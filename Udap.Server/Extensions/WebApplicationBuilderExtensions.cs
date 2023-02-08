#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Udap.Server.Configuration;

namespace Udap.Server.Extensions;

public static class WebApplicationBuilderExtensions
{
    public static WebApplicationBuilder AddUdapServerSettings(
        this WebApplicationBuilder builder,
        ServerSettings? serverSettings = null)
    {
        serverSettings ??= builder.Configuration.GetOption<ServerSettings>("ServerSettings");

        builder.Services.AddSingleton<ServerSettings>(serverSettings);

        return builder;
    }
}
