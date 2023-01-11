#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


using System.Diagnostics;

namespace Udap.Common.Extensions;
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
}
