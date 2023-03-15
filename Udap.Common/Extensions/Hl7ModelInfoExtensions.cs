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

/// <summary>
/// By default these extensions will build scopes that would be used on a typical UDAP server.
/// </summary>
public static class Hl7ModelInfoExtensions
{
    public static HashSet<string> BuildHl7FhirV1AndV2Scopes(List<string> prefixes, string v1Suffix = "read", string v2Suffix = "rs")
    {
        var scopes = new HashSet<string>();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV1Scopes(prefix, v1Suffix, scopes);
            BuildHl7FhirV2Scopes(prefix, v2Suffix, scopes);
        }

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirV1AndV2Scopes(string prefix, string v1Suffix = "read", string v2Suffix = "rs", HashSet<string>? scopes = null)
    {
        scopes ??= new HashSet<string>();

        foreach (var resName in ModelInfo.SupportedResources)
        {
            scopes.Add($"{prefix}/{resName}.{v1Suffix}");
        }

        scopes.Add($"{prefix}/*.{v1Suffix}");

        foreach (var resName in ModelInfo.SupportedResources)
        {
            scopes.Add($"{prefix}/{resName}.{v2Suffix}");
        }

        scopes.Add($"{prefix}/*.{v2Suffix}");

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirV2Scopes(List<string> prefixes, string suffix = "rs")
    {
        var scopes = new HashSet<string>();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV2Scopes(prefix, suffix, scopes);
        }

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirV2Scopes(string prefix, string suffix = "rs", HashSet<string>? scopes = null)
    {
        scopes ??= new HashSet<string>();

        foreach (var resName in ModelInfo.SupportedResources)
        {
            scopes.Add($"{prefix}/{resName}.{suffix}");
        }

        scopes.Add($"{prefix}/*.{suffix}");
        
        return scopes;
    }
    public static HashSet<string> BuildHl7FhirV1Scopes(List<string> prefixes, string suffix = "read")
    {
        var scopes = new HashSet<string>();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV1Scopes(prefix, suffix, scopes);
        }

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirV1Scopes(string prefix, string suffix = "read", HashSet<string>? scopes = null)
    {
        scopes ??= new HashSet<string>();

        foreach (var resName in ModelInfo.SupportedResources)
        {
            scopes.Add($"{prefix}/{resName}.{suffix}");
        }

        scopes.Add($"{prefix}/*.{suffix}");

        return scopes;
    }

}
