#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Builder;
using Udap.Server.Hosting;

namespace Udap.Server.Configuration;
public static class UdapServerApplicationBuilderExtensions
{
    public static IApplicationBuilder UseUdapServer(this IApplicationBuilder app)
    {
        app.UseMiddleware<UdapAuthorizationResponseMiddleware>();
        app.UseMiddleware<UdapTokenResponseMiddleware>();

        return app;
    }
}
