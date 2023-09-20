#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Util.Extensions;
public static class StringExtensions
{
    [DebuggerStepThrough]
    public static string ToCrLf(this string input)
    {
        return input
            .Replace("\r\n", "\n")
            .Replace("\r", "\n")
            .Replace("\n", "\r\n");
    }
    
    [DebuggerStepThrough]
    public static string ToLf(this string input)
    {
        return input
            .Replace("\r\n", "\n")
            .Replace("\r", "\n");
    }

    [DebuggerStepThrough]
    public static IEnumerable<string> FromSpaceSeparatedString(this string input)
    {
        input = input.Trim();
        return input.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    public static string DecodeJwtHeader(this string input)
    {
        return Base64UrlEncoder.Decode(input);
    }

    [DebuggerStepThrough]
    public static string ToSpaceSeparatedString(this ICollection<string>? list)
    {
        if (list == null)
        {
            return string.Empty;
        }

        return list.Any() ? string.Join(" ", list): string.Empty;
    }
#if NET6_0_OR_GREATER
    [DebuggerStepThrough]
    public static string ToSpaceSeparatedString(this IEnumerable<string>? list)
    {
        if (list == null)
        {
            return string.Empty;
        }

        return string.Join(' ', list);
    }
#endif

    [DebuggerStepThrough]
    public static bool IsECDSA(this string input)
    {
        return input.StartsWith("ES");
    }
}