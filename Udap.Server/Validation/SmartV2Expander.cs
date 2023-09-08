#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.RegularExpressions;

namespace Udap.Server.Validation;

public class SmartV2Expander : IScopeExpander
{
    /// <summary>
    /// Expands scope parameters to a set of discrete scopes.
    /// Implement logic to determine if a scope represents a pattern that can be expanded.
    /// </summary>
    /// <param name="scopes">The scope parameter value.</param>
    /// <returns>A set of discrete scopes.</returns>
    public IEnumerable<string> Expand(IEnumerable<string> scopes)
    {
        var expandedScopes = new HashSet<string>();

        foreach (var scope in scopes.ToList())
        {
            if (scope.EndsWith(".read"))
            {
                expandedScopes.Add(scope);
                continue;
            }

            var regex = new Regex("^(system|user|patient)[\\/].*\\.[cruds]+$");
            var matches = regex.Matches(scope);


            foreach (Match match in matches)
            {
                var value = match.Value;
                var parts = value.Split('.');
                var parameters = parts[1].ToList();

                foreach (var parameter in parameters)
                {
                    expandedScopes.Add($"{parts[0]}.{parameter}");
                }
            }
        }

        return expandedScopes;
    }
}