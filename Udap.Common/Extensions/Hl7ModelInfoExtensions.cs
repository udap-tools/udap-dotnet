#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Model;

namespace Udap.Common.Extensions;
public static class Hl7ModelInfoExtensions
{
    public static HashSet<string> BuildHl7FhirScopes(List<string> prefixes, string cruds = "cruds")
    {
        var scopes = new HashSet<string>();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirScopes(prefix: prefix, scopes: scopes);
        }

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirScopes(string prefix, string cruds = "cruds", HashSet<string>? scopes = null)
    {
        scopes ??= new HashSet<string>();

        foreach (var resName in ModelInfo.SupportedResources)
        {
            scopes.Add($"{prefix}/{resName}.{cruds}");
        }

        scopes.Add($"{prefix}/*.{cruds}");
        
        return scopes;
    }
}
