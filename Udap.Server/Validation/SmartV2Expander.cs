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
using static System.Formats.Asn1.AsnWriter;

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
            var regex = new Regex("^(system|user|patient)[\\/].*\\.[cruds]+$");
            var matches = regex.Matches(scope);

            if (matches.Any())
            {
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
            else
            {
                expandedScopes.Add(scope);
            }
        }

        return expandedScopes;
    }

    public IEnumerable<ApiScope> ExpandToApiScopes(string scope)
    {
        var expandedScopes = Expand(new List<string> { scope });

        return expandedScopes.Select(s => new ApiScope(s));
    }

    /// <summary>
    /// Shrinks scope parameters.
    /// </summary>
    /// <param name="scopes"></param>
    /// <returns></returns>
    public IEnumerable<string> Shrink(IEnumerable<string> scopes)
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
            string groupingSuffix = "";

            foreach (var item in scopeGroup
                         .OrderBy(sg =>
                         {
                             var index = fixedOrder.IndexOf(sg.Key.Item2);
                             return index == -1 ? int.MaxValue : index;
                         }))
            {
                groupingSuffix += item.Key.Item2;
            }

            shrunkScopes.Add($"{groupingPrefix}.{groupingSuffix}");
        }
        
        shrunkScopes.ToList().AddRange(unmatchedScopes.ToList());

        return shrunkScopes;
    }
}