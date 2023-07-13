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
    public static string EnsureTrailingSlash(this string url)
    {
        if (!url.EndsWith("/"))
        {
            return url + "/";
        }

        return url;
    }

    [DebuggerStepThrough]
    public static string EnsureLeadingSlash(this string? url)
    {
        if (url != null && !url.StartsWith("/"))
        {
            return "/" + url;
        }

        return string.Empty;
    }

    [DebuggerStepThrough]
    public static bool IsPresent(this string? value)
    {
        return !string.IsNullOrWhiteSpace(value);
    }



    [DebuggerStepThrough]
    public static bool IsMissing(this string value)
    {
        return string.IsNullOrWhiteSpace(value);
    }

    [DebuggerStepThrough]
    public static string RemoveTrailingSlash(this string url)
    {
        if (url.EndsWith("/"))
        {
            url = url.Substring(0, url.Length - 1);
        }
    
        return url;
    }

    [DebuggerStepThrough]
    public static string GetBaseUrlFromMetadataUrl(this string url)
    {
        var index = url.IndexOf(".well-known/udap", StringComparison.OrdinalIgnoreCase);
        if (index != -1)
        {
            url = url[..(index - 1)];
        }

        var uri = new Uri(url);

        return uri.AbsoluteUri;
    }


    [DebuggerStepThrough]
    public static string? GetCommunityFromQueryParams(this string queryPath)
    {
        var parameters = queryPath.Split('&');

        var community = parameters.FirstOrDefault(x => 
            x.StartsWith("community=", StringComparison.OrdinalIgnoreCase));

        if (community == null)
        {
            return null;
        }

        return community!.Split("=").LastOrDefault();
    }
}
