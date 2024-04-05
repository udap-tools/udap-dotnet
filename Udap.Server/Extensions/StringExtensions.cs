#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Udap.Server.Extensions;

internal static class StringExtensions
{
    // [DebuggerStepThrough]
    // public static string EnsureLeadingSlash(this string? url)
    // {
    //     if (url != null && !url.StartsWith("/"))
    //     {
    //         return "/" + url;
    //     }
    //
    //     return string.Empty;
    // }
    //
    // [DebuggerStepThrough]
    // public static bool IsPresent(this string? value)
    // {
    //     return !string.IsNullOrWhiteSpace(value);
    // }
    //
    // [DebuggerStepThrough]
    // public static string EnsureTrailingSlash(this string url)
    // {
    //     if (!url.EndsWith("/"))
    //     {
    //         return url + "/";
    //     }
    //
    //     return url;
    // }
    //
    // [DebuggerStepThrough]
    // public static bool IsMissing(this string value)
    // {
    //     return string.IsNullOrWhiteSpace(value);
    // }

 
    public static string ToSnakeCase(this string input)
    {
        if (string.IsNullOrEmpty(input)) { return input; }

        var startUnderscores = Regex.Match(input, @"^_+");
        return startUnderscores + Regex.Replace(input, @"([a-z0-9])([A-Z])", "$1_$2").ToLower();
    }
 
}
