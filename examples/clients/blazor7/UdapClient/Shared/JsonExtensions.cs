#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;

namespace UdapClient.Shared;
public static class JsonExtensions
{
    public static string AsJson<T>(this T source)
    {
        var options = new JsonSerializerOptions();
        options.WriteIndented = true;
        

        return JsonSerializer.Serialize<T>(source, options);
    }
}
