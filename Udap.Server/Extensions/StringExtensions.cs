#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Udap.Server.Extensions;

internal static partial class StringExtensions
{
    [DebuggerStepThrough]
    public static string ToSnakeCase(this string input)
    {
        if (string.IsNullOrEmpty(input)) { return input; }

        var startUnderscores = MyRegex().Match(input);
        return startUnderscores + MyRegex1().Replace(input, "$1_$2").ToLower();
    }

    [GeneratedRegex(@"^_+")]
    private static partial Regex MyRegex();
    [GeneratedRegex(@"([a-z0-9])([A-Z])")]
    private static partial Regex MyRegex1();
}
