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

public class CertificateChainNodeViewModel
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public DateTime NotAfter { get; set; }
    public CertificateStatus Status { get; set; }

    /// <summary>
    /// "RootCA", "IntermediateCA", "EndEntity", or "CRL".
    /// </summary>
    public string CertificateRole { get; set; } = string.Empty;

    /// <summary>
    /// Entity type for navigation: "CaCertificate", "IssuedCertificate", or "Crl".
    /// </summary>
    public string EntityType { get; set; } = string.Empty;

    /// <summary>
    /// Key storage type: "local", "vault-transit", or null (no private key / CRL).
    /// </summary>
    public string? KeyStorage { get; set; }

    /// <summary>
    /// For remote-keyed entries, the provider-specific key identifier (e.g. Vault Transit
    /// key name). Used to verify the key still exists in the remote provider.
    /// </summary>
    public string? KeyIdentifier { get; set; }

    public bool IsSuperseded { get; set; }

    /// <summary>
    /// For remote-keyed certificates (Vault Transit, GCP KMS): true when the remote
    /// signing key is missing in the provider (e.g. Vault dev mode was restarted).
    /// null = not checked or not applicable (local key).
    /// </summary>
    public bool? RemoteKeyMissing { get; set; }

    /// <summary>
    /// For CA nodes: freshness of the most recently published CRL. Surfaced on the tree
    /// row so operators can spot an expired CRL without expanding the node.
    /// </summary>
    public CrlFreshness LatestCrlFreshness { get; set; } = CrlFreshness.Missing;

    /// <summary>
    /// For CRL nodes: true when this is the most recent (highest CrlNumber) non-archived
    /// CRL for its issuing CA. Re-publishing only makes sense for the latest CRL.
    /// </summary>
    public bool IsLatestCrl { get; set; }

    public List<CertificateChainNodeViewModel> Children { get; set; } = new();
}

public enum CrlFreshness
{
    Missing,
    Fresh,
    ExpiringSoon,
    Expired
}
