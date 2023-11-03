#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Models;

namespace Udap.Server.Validation.Default;
public class DefaultScopeExpander : IScopeExpander
{

    /// <summary>
    /// Default implementation of IScopeExpander.  It does nothing.
    /// </summary>
    /// <param name="scopes">The scope parameter value.</param>
    /// <returns>A set of discrete scopes.</returns>
    public IEnumerable<string> Expand(IEnumerable<string> scopes)
    {
        return scopes;
    }

    /// <summary>
    /// If the a wildcard is present such as a * then the implementation should expand accordingly.
    /// </summary>
    /// <param name="clientScopes"></param>
    /// <param name="apiScopes"></param>
    /// <returns></returns>
    public IEnumerable<string> WildCardExpand(ICollection<string> clientScopes, ICollection<string> apiScopes)
    {
        return clientScopes;
    }

    /// <summary>
    /// Shrinks scope parameters.
    /// </summary>
    /// <param name="scopes"></param>
    /// <returns></returns>
    public IEnumerable<string> Aggregate(IEnumerable<string> scopes)
    {
        return scopes;
    }
}
