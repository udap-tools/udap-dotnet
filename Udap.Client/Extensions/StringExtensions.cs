﻿#region (c) 2022 Joseph Shook. All rights reserved.
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
    public static string AssertUri(this string? uri)
    {
       if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? _))
       {
           throw new UriFormatException(uri);
       }

       return uri;
    }
}