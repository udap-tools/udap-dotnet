#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.ViewModels;

public enum ComponentStatus
{
    NotConfigured,
    Reachable,
    Unreachable
}

public record SystemStatusViewModel(
    bool DatabaseConnected,
    string? DatabaseError,
    string DefaultProvider,
    List<string> AvailableProviders,
    ComponentStatus VaultStatus,
    string? VaultAddress,
    ComponentStatus GcpKmsStatus,
    string? GcpProjectId,
    DateTimeOffset CheckedAt)
{
    public bool IsHealthy =>
        DatabaseConnected &&
        VaultStatus != ComponentStatus.Unreachable &&
        GcpKmsStatus != ComponentStatus.Unreachable;

    public bool IsCritical => !DatabaseConnected;
}
