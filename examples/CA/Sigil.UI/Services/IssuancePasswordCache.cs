#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.UI.Services;

/// <summary>
/// Per-Blazor-circuit cache for PFX passwords entered during certificate issuance.
/// Scoped lifetime means the cache is cleared when the user disconnects or refreshes.
/// Never persisted to disk or shared across users.
/// </summary>
public class IssuancePasswordCache
{
    private readonly Dictionary<string, string> _cache = new();

    public string? Get(string key) => _cache.TryGetValue(key, out var value) ? value : null;

    public void Save(string key, string password) => _cache[key] = password;

    public void Clear(string key) => _cache.Remove(key);
}
