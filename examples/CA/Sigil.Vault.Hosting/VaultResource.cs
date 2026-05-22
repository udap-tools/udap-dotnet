#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Aspire.Hosting.ApplicationModel;

namespace Sigil.Vault.Hosting;

/// <summary>
/// Represents a HashiCorp Vault container resource for Aspire orchestration.
/// </summary>
public sealed class VaultResource(string name) : ContainerResource(name), IResourceWithConnectionString
{
    internal const string HttpEndpointName = "http";
    internal const int DefaultPort = 8200;

    private EndpointReference? _primaryEndpointReference;

    /// <summary>
    /// The primary HTTP endpoint for the Vault API.
    /// </summary>
    public EndpointReference PrimaryEndpoint =>
        _primaryEndpointReference ??= new EndpointReference(this, HttpEndpointName);

    /// <summary>
    /// The root token used for authentication in dev mode.
    /// </summary>
    public string RootToken { get; set; } = "root-token";

    /// <summary>
    /// Transit key specs to be created after Vault starts.
    /// </summary>
    internal List<TransitKeySpec> TransitKeys { get; } = [];

    /// <summary>
    /// When true, Vault runs in server mode with file-backed persistent storage.
    /// Init keys / root token are saved to <see cref="HostInitStatePath"/>.
    /// When false (default), Vault runs in dev mode (in-memory, wiped on every restart).
    /// </summary>
    internal bool IsPersistent { get; set; }

    /// <summary>
    /// Host filesystem path where init state (root token + unseal keys) is persisted.
    /// Only meaningful when <see cref="IsPersistent"/> is true.
    /// </summary>
    internal string? HostInitStatePath { get; set; }

    /// <summary>
    /// Connection string expression returning the Vault HTTP address.
    /// </summary>
    public ReferenceExpression ConnectionStringExpression =>
        ReferenceExpression.Create(
            $"{PrimaryEndpoint.Property(EndpointProperty.Scheme)}://{PrimaryEndpoint.Property(EndpointProperty.Host)}:{PrimaryEndpoint.Property(EndpointProperty.Port)}");
}
