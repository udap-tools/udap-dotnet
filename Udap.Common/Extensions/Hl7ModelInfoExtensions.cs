﻿#region (c) 2023 Joseph Shook. All rights reserved.
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
    public static HashSet<string> BuildHl7FhirV1AndV2Scopes(
        List<string> prefixes,
        Func<string, bool>? specification = null,
        string v1Suffix = "read",
        string v2Suffix = "rs")
    {
        var scopes = new HashSet<string>();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV1Scopes(prefix, specification, v1Suffix, scopes);
            BuildHl7FhirV2Scopes(prefix, specification, v2Suffix, scopes);
        }

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirV1AndV2Scopes(
        string prefix, 
        Func<string, bool>? specification = null,
        string v1Suffix = "read",
        string v2Suffix = "rs",
        HashSet<string>? scopes = null)
    {
        scopes ??= [];

        BuildHl7FhirV1Scopes(prefix, specification, v1Suffix, scopes);
        BuildHl7FhirV2Scopes(prefix, specification, v2Suffix, scopes);

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirV2Scopes(List<string> prefixes, Func<string, bool>? specification = null, string suffix = "rs")
    {
        var scopes = new HashSet<string>();
        var parameters = suffix.ToList();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV2Scopes(prefix, specification, suffix, scopes);
        }

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirV2Scopes(
        string prefix,
        Func<string, bool>? specification = null,
        string suffix = "rs",
        HashSet<string>? scopes = null)
    {
        scopes ??= [];
        specification ??= r => true;
        var parameters = ScopeExtensions.GenerateCombinations(suffix);

        foreach (var parameter in parameters)
        {
            foreach (var resName in ModelInfo.SupportedResources.Where(specification))
            {
                scopes.Add($"{prefix}/{resName}.{parameter}");
            }

            scopes.Add($"{prefix}/*.{parameter}");
        }

        return scopes;
    }
    public static HashSet<string> BuildHl7FhirV1Scopes(List<string> prefixes, Func<string, bool>? specification = null, string suffix = "read")
    {
        var scopes = new HashSet<string>();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV1Scopes(prefix, specification, suffix, scopes);
        }

        return scopes;
    }

    public static HashSet<string> BuildHl7FhirV1Scopes(
        string prefix,
        Func<string, bool>? specification = null,
        string suffix = "read",
        HashSet<string>? scopes = null)
    {
        scopes ??= [];
        specification ??= r => true;

        foreach (var resName in ModelInfo.SupportedResources.Where(specification))
        {
            scopes.Add($"{prefix}/{resName}.{suffix}");
        }

        scopes.Add($"{prefix}/*.{suffix}");

        return scopes;
    }
}
