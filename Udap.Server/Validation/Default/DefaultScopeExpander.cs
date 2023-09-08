#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

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
}
