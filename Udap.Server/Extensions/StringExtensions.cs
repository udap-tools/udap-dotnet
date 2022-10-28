#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;

namespace Udap.Server.Extensions
{
    public static class StringExtensions
    {
        [DebuggerStepThrough]
        public static string EnsureLeadingSlash(this string? url)
        {
            if (url != null && !url.StartsWith("/"))
            {
                return "/" + url;
            }

            return string.Empty;
        }
    }
}
