#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;

namespace UdapEd.Shared;
public static class JsonExtensions
{
    public static string AsJson<T>(this T source)
    {
        var options = new JsonSerializerOptions();
        options.WriteIndented = true;
        

        return JsonSerializer.Serialize(source, options);
    }

    private const string IndentString = "  ";

    /// <summary>
    /// Routine is from https://stackoverflow.com/questions/4580397/json-formatter-in-c/24782322#24782322
    /// </summary>
    /// <param name="json"></param>
    /// <returns></returns>
    public static string FormatJson(string json)
    {

        int indentation = 0;
        int quoteCount = 0;
        var result =
            from ch in json
            let quotes = ch == '"' ? quoteCount++ : quoteCount
            let lineBreak = ch == ',' && quotes % 2 == 0 ? ch + Environment.NewLine + String.Concat(Enumerable.Repeat(IndentString, indentation)) : null
            let openChar = ch == '{' || ch == '[' ? ch + Environment.NewLine + String.Concat(Enumerable.Repeat(IndentString, ++indentation)) : ch.ToString()
            let closeChar = ch == '}' || ch == ']' ? Environment.NewLine + String.Concat(Enumerable.Repeat(IndentString, --indentation)) + ch : ch.ToString()
            select lineBreak == null
                ? openChar.Length > 1
                    ? openChar
                    : closeChar
                : lineBreak;

        return String.Concat(result);
    }
}
