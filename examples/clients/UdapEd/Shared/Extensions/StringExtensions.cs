#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Maui.Storage;

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

    public static string ToMauiAppScheme(this string uriString)
    {
        var uri = new Uri(uriString);

        if (uri.Scheme == "http" || uri.Scheme == "https")
        {
            return $"mauiapp{Uri.SchemeDelimiter}{uri.Authority}{uri.AbsolutePath}";
        }

        return uriString;
    }

    public static ICollection<string> ToMauiAppSchemes(this IEnumerable<string> uriStrings)
    {
        var mauiAppSchemes = new List<string>();

        foreach (var uriString in uriStrings)
        {
            var uri = new Uri(uriString);

            if (uri.Scheme == "http" || uri.Scheme == "https")
            {
                var redirectUri = $"mauiapp{Uri.SchemeDelimiter}{uri.Authority}{uri.AbsolutePath}";
                mauiAppSchemes.Add(redirectUri);
            }
            else
            {
                mauiAppSchemes.Add(uriString);
            }
        }

        return mauiAppSchemes;
    }
}
