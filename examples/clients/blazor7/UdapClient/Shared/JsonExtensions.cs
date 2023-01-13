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
