#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Vault.Hosting;

/// <summary>
/// Persistent state captured during Vault initialization. Required to unseal Vault on
/// every container restart. Stored on the host filesystem (not in the Docker volume) so
/// the unseal keys are accessible to the Aspire AppHost.
///
/// SECURITY: for dev use only. Plain JSON on disk with no encryption. Don't use this
/// pattern in production.
/// </summary>
public sealed record VaultInitState(
    [property: JsonPropertyName("rootToken")] string RootToken,
    [property: JsonPropertyName("unsealKeys")] List<string> UnsealKeys);

public static class VaultInitStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string GetDefaultPath(string resourceName)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(appData, "Sigil", $"vault-{resourceName}-init.json");
    }

    public static VaultInitState? TryLoad(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            return JsonSerializer.Deserialize<VaultInitState>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    public static void Save(string path, VaultInitState state)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(state, JsonOptions));
    }
}
