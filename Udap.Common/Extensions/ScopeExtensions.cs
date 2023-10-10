#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text;

namespace Udap.Common.Extensions;
public static class ScopeExtensions
{
    public static List<string> GenerateCombinations(string input)
    {
        var result = new List<string>();
        GenerateCombinationsRecursive(input.ToCharArray(), 0, new StringBuilder(), result);
        return result;
    }

    private static void GenerateCombinationsRecursive(char[] input, int index, StringBuilder current, List<string> result)
    {
        if (index == input.Length)
        {
            if (current.Length > 0)
            {
                result.Add(current.ToString());
            }

            return;
        }

        var nextChar = input[index];
        current.Append(nextChar);
        GenerateCombinationsRecursive(input, index + 1, current, result);
        current.Remove(current.Length - 1, 1);
        GenerateCombinationsRecursive(input, index + 1, current, result);
    }
}
