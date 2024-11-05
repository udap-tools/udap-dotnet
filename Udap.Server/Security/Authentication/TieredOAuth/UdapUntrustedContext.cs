#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Udap.Server.Security.Authentication.TieredOAuth;
public class UdapUntrustedContext : ResultContext<TieredOAuthAuthenticationOptions>
{
    /// <summary>
    /// Initializes a new instance of <see cref="T:Microsoft.AspNetCore.Authentication.ResultContext`1" />.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/></param>
    /// <param name="scheme">The <see cref="AuthenticationScheme"/></param>
    /// <param name="options">The <see cref="TieredOAuthAuthenticationOptions"/> associated with the scheme.</param>
    /// <param name="properties">The <see cref="AuthenticationProperties"/></param>
    public UdapUntrustedContext(
        HttpContext context, 
        AuthenticationScheme scheme, 
        TieredOAuthAuthenticationOptions options,
        AuthenticationProperties properties) : base(context, scheme, options)
    {
        foreach (var prop in properties.Parameters.Where(p => p.Key == "Untrusted").Select(p => p))
        {
            context.Response.Headers.Append(prop.Key, new StringValues(prop.Value?.ToString()));
        }
    }
}
