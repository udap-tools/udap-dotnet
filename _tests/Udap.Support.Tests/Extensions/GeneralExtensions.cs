﻿#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IO;

namespace Udap.Support.Tests.Extensions;

public static class GeneralExtensions
{
    public static void EnsureDirectoryExists(this string source)
    {
        if (!Directory.Exists(source))
        {
            Directory.CreateDirectory(source);
        }
    }
}