#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.RegularExpressions;
using Duende.IdentityServer.Models;
using Udap.Common.Extensions;

namespace Udap.Server.Validation;

/// <summary>
/// Implements rules to expand scopes where the scope parameter part may represent an encoded set of scopes.
///
/// From HL7 FHIR SMART v2 the parameters portion of system/Patient.crud can be expanded to discrete scopes.  For example::
///
/// system/Patient.c
/// system/Patient.r
/// system/Patient.u
/// system/Patient.d
///
/// </summary>
public class HL7SmartScopeExpander : IScopeExpander
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
            var smartV2Regex = new Regex(@"^(system|user|patient)[\/].*\.[cruds]+$");
            var smartV2Matches = smartV2Regex.Matches(scope);

            var smartV1Regex = new Regex(@"^(system|user|patient)[\/].*\.(read|write)$");
            var smartV1Matches = smartV1Regex.Matches(scope);

            if (smartV2Matches.Any()) // Expand SMART V2 Scopes
            {
                foreach (Match match in smartV2Matches)
                {
                    var value = match.Value;
                    var parts = value.Split('.');
                    
                    var combinations = ScopeExtensions.GenerateCombinations(parts[1]);

                    foreach (var parameter in combinations)
                    {
                        expandedScopes.Add($"{parts[0]}.{parameter}");
                    }
                }
            }
            else if (smartV1Matches.Any()) // Just keep SMART V1 scopes
            {
                expandedScopes.Add(scope);
            }
            else
            {
                if (!scope.Contains('*'))
                {
                    expandedScopes.Add(scope);
                }
            }
        }

        return expandedScopes;
    }

    public IEnumerable<ApiScope> ExpandToApiScopes(string scope)
    {
        var expandedScopes = Expand(new List<string> { scope.Trim() });

        return expandedScopes.Select(s => new ApiScope(s));
    }

    /// <summary>
    /// Expand * resources.  
    /// </summary>
        /// <param name="clientScopes"></param>
    /// <param name="apiScopes"></param>
    /// <returns></returns>
    public IEnumerable<string> WildCardExpand(ICollection<string> clientScopes, ICollection<string> apiScopes)
    {
        var expandedScopes = new HashSet<string>();
       
        foreach (var scope in clientScopes.Where(s => s.Contains('*')))
        {
            var smartV2Regex = new Regex(@"^(system|user|patient)\/\*\.[cruds]+$");
            var smartV2Matches = smartV2Regex.Matches(scope);

            var smartV1Regex = new Regex(@"^(system|user|patient)\/\*\.(read|write)$");
            var smartV1Matches = smartV1Regex.Matches(scope);

            if (smartV2Matches.Any())
            {
                foreach (Match match in smartV2Matches)
                {
                    var value = match.Value;
                    var parts = value.Split('*');

                    var specificScopes = apiScopes.Where(s => s.StartsWith(parts[0]) &&
                                                              s.EndsWith(parts[1]));

                    foreach (var specificScope in specificScopes)
                    {
                        expandedScopes.Add(specificScope);
                    }
                }
            }
            else if (smartV1Matches.Any())
            {
                foreach (Match match in smartV1Matches)
                {
                    var value = match.Value;
                    var parts = value.Split('*');

                    var specificScopes = apiScopes.
                        Where(s => s.StartsWith(parts[0]) &&
                                   s.EndsWith(parts[1]));

                    foreach (var specificScope in specificScopes)
                    {
                        expandedScopes.Add(specificScope);
                    }
                }
            }
            else
            {
                expandedScopes.Add(scope);
            }
        }

        foreach (var scope in clientScopes.Where(s => !s.Contains('*')))
        {
            expandedScopes.Add(scope);
        }

        return expandedScopes;
    }

    /// <summary>
    /// Shrinks scope parameters.
    /// </summary>
    /// <param name="scopes"></param>
    /// <returns></returns>
    public IEnumerable<string> Aggregate(IEnumerable<string> scopes)
    {
        var matchedScopes = new HashSet<string>();
        var unmatchedScopes = new HashSet<string>();
        //todo cache this
        var fixedOrder = new List<string> { "c", "r", "u", "d", "s" };

        foreach (var scope in scopes)
        {
            var regex = new Regex("^(system|user|patient)[\\/].*\\.[c|r|u|d|s]+$");
            if (regex.IsMatch(scope))
            {
                matchedScopes.Add(scope);
            }
            else
            {
                unmatchedScopes.Add(scope);
            }
        }

        var scopeGroups = matchedScopes
            .Select(s =>
            {
                var parts = s.Split('.');

                return (parts[0], parts[1]);
            })
            .GroupBy((g) => (g.Item1, g.Item2))
            ;

        var shrunkScopes = new HashSet<string>();

        foreach (var scopeGroup in scopeGroups
                     .GroupBy(sc => sc.Key.Item1)
                     .Select(sc => sc))
        {
            string groupingPrefix = scopeGroup.First().Key.Item1;
            string groupingSuffix = scopeGroup.OrderByDescending(g => g.Key.Item2.Length).First().Key.Item2;
            
            shrunkScopes.Add($"{groupingPrefix}.{groupingSuffix}");
        }

        foreach (var unmatchedScope in unmatchedScopes)
        {
            shrunkScopes.Add(unmatchedScope);
        }

        return shrunkScopes.OrderBy(s => s);
    }
}