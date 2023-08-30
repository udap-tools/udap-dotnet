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
    /// <param name="context">The context.</param>
    /// <param name="scheme">The authentication scheme.</param>
    /// <param name="options">The authentication options associated with the scheme.</param>
    public UdapUntrustedContext(
        HttpContext context, 
        AuthenticationScheme scheme, 
        TieredOAuthAuthenticationOptions options,
        AuthenticationProperties properties) : base(context, scheme, options)
    {
        foreach (var prop in properties.Parameters.Where(p => p.Key == "Untrusted").Select(p => p))
        {
            context.Response.Headers.Add(prop.Key, new StringValues(prop.Value?.ToString()));
        }
    }
}
