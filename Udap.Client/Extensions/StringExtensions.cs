#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;

namespace Udap.Client.Extensions;

public static class StringExtensions
{
    [DebuggerStepThrough]
    public static bool IsUri(this string? uri)
    {
        return Uri.TryCreate(uri, UriKind.Absolute, out Uri? result);
    }

    [DebuggerStepThrough]
    public static string AssertUri(this string? uri)
    {
       if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? result))
       {
           throw new UriFormatException(
               "Community SHALL be a URI.  See https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#multiple-trust-communities");
       }

       return uri;
    }
}