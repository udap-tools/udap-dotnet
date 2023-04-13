#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;

namespace Udap.Client.Internal;

public static class InternalStringExtensions
{
    [DebuggerStepThrough]
    public static bool IsMissing(this string value)
    {
        return string.IsNullOrWhiteSpace(value);
    }

    [DebuggerStepThrough]
    public static bool IsPresent(this string value)
    {
        return !(value.IsMissing());
    }

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
        url = url.Substring(0, url.IndexOf(".well-known/udap"));

        return url;
    }
    
}