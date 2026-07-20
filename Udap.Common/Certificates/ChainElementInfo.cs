#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Models;

namespace Udap.Common.Certificates;

/// <summary>
/// Represents a certificate in a validated chain along with any validation problems.
/// This is a platform-independent replacement for <see cref="X509ChainElement"/>
/// that works with BouncyCastle chain validation.
/// </summary>
public class ChainElementInfo
{
    /// <summary>
    /// Initializes a new instance with no validation problems.
    /// </summary>
    /// <param name="certificate">The certificate at this position in the chain.</param>
    public ChainElementInfo(X509Certificate2 certificate)
    {
        Certificate = certificate;
    }

    /// <summary>
    /// Initializes a new instance with the specified validation problems.
    /// </summary>
    /// <param name="certificate">The certificate at this position in the chain.</param>
    /// <param name="problems">The validation problems found for this certificate.</param>
    public ChainElementInfo(X509Certificate2 certificate, IReadOnlyList<ChainProblem> problems)
    {
        Certificate = certificate;
        Problems = problems;
    }

    /// <summary>
    /// The certificate at this position in the chain.
    /// </summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// Validation problems found for this certificate, if any.
    /// </summary>
    public IReadOnlyList<ChainProblem> Problems { get; } = Array.Empty<ChainProblem>();

    /// <summary>
    /// Returns true if this element has any validation problems.
    /// </summary>
    public bool HasProblems => Problems.Count > 0;
}

/// <summary>
/// Describes a single validation problem found during chain validation.
/// </summary>
public class ChainProblem
{
    /// <summary>
    /// Initializes a new instance with the specified status and description.
    /// </summary>
    /// <param name="status">The problem status flag.</param>
    /// <param name="statusInformation">A human-readable description of the problem.</param>
    public ChainProblem(ChainProblemStatus status, string statusInformation)
    {
        Status = status;
        StatusInformation = statusInformation;
    }

    /// <summary>Gets the problem status flag.</summary>
    public ChainProblemStatus Status { get; }

    /// <summary>Gets a human-readable description of the validation problem.</summary>
    public string StatusInformation { get; }
}

/// <summary>
/// Status flags for chain validation problems.
/// Maps conceptually to <see cref="X509ChainStatusFlags"/> but is platform-independent.
/// </summary>
[Flags]
public enum ChainProblemStatus
{
    /// <summary>No problems detected.</summary>
    None = 0,
    /// <summary>The certificate is outside its validity period.</summary>
    NotTimeValid = 1,
    /// <summary>The certificate has been revoked.</summary>
    Revoked = 2,
    /// <summary>The certificate signature is invalid.</summary>
    NotSignatureValid = 4,
    /// <summary>The certificate has invalid CA basic constraints.</summary>
    InvalidBasicConstraints = 8,
    /// <summary>Revocation information is unavailable (offline).</summary>
    OfflineRevocation = 16,
    /// <summary>The root certificate is not trusted.</summary>
    UntrustedRoot = 32,
    /// <summary>The certificate chain is incomplete.</summary>
    PartialChain = 64,
    /// <summary>No CRL distribution point was found on the certificate.</summary>
    CrlNotFound = 128,
    /// <summary>The CRL could not be downloaded.</summary>
    CrlFetchFailed = 256,
    /// <summary>The revocation status of the certificate could not be determined.</summary>
    RevocationStatusUnknown = 512
}

/// <summary>
/// Result of chain validation, returned by async validation methods.
/// Replaces the out parameters from the synchronous API.
/// </summary>
public class ChainValidationResult
{
    /// <summary>
    /// Initializes a new instance with the specified validation outcome.
    /// </summary>
    /// <param name="isValid">Whether the chain is valid and trusted.</param>
    /// <param name="chainElements">The chain elements with their validation problems.</param>
    /// <param name="communityId">The community identifier from the matching trust anchor, if resolved.</param>
    /// <param name="communityName">The community name (URI) from the matching trust anchor, if resolved.</param>
    /// <param name="matchedAnchor">The trust anchor the certificate chained to, if resolved.</param>
    public ChainValidationResult(bool isValid, IReadOnlyList<ChainElementInfo> chainElements, long? communityId = null, string? communityName = null, Anchor? matchedAnchor = null)
    {
        IsValid = isValid;
        ChainElements = chainElements;
        CommunityId = communityId;
        CommunityName = communityName;
        MatchedAnchor = matchedAnchor;
    }

    /// <summary>Gets whether the certificate chain is valid and trusted.</summary>
    public bool IsValid { get; }

    /// <summary>Gets the chain elements with their associated validation problems.</summary>
    public IReadOnlyList<ChainElementInfo> ChainElements { get; }

    /// <summary>Gets the community identifier from the matching trust anchor, or <c>null</c> if not resolved.</summary>
    public long? CommunityId { get; }

    /// <summary>Gets the community name (URI) from the matching trust anchor, or <c>null</c> if not resolved.</summary>
    public string? CommunityName { get; }

    /// <summary>
    /// Gets the <see cref="Anchor"/> the end-entity certificate chained to, or <c>null</c> if the
    /// chain was validated without caller-supplied <see cref="Anchor"/> models or no anchor matched.
    /// Resolved by thumbprint against the anchors passed to
    /// <see cref="TrustChainValidator.IsTrustedCertificateAsync(string, X509Certificate2, X509Certificate2Collection?, X509Certificate2Collection, IEnumerable{Anchor}?, System.Threading.CancellationToken)"/>.
    /// </summary>
    public Anchor? MatchedAnchor { get; }
}
