#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Extensions;
public static class StringExtensions
{
    public static string TrimForDisplay(this string input, int length, string? suffix)
    {
        if (input.Length > length)
        {
            input = input.Substring(0, length);
            if (suffix != null)
            {
                input += suffix;
            }
        }

        return input;
    }
}
