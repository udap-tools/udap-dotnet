#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


namespace Udap.Common.Extensions;
public static class StringExtensions
{
    public static string ToCrLf(this string input)
    {
        return input
            .Replace("\r\n", "\n")
            .Replace("\r", "\n")
            .Replace("\n", "\r\n");
    }

    public static string ToLf(this string input)
    {
        return input
            .Replace("\r\n", "\n")
            .Replace("\r", "\n");
    }
}
