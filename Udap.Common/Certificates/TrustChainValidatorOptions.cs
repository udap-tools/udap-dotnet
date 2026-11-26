#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Certificates;

/// <summary>
/// Optional policy applied by <see cref="TrustChainValidator"/> on top of standard chain validation.
/// Nothing here is enforced unless it is configured, so the defaults keep the validator's behaviour unchanged.
/// </summary>
/// <remarks>
/// Bind it from configuration with
/// <c>services.Configure&lt;TrustChainValidatorOptions&gt;(configuration.GetSection(TrustChainValidatorOptions.SectionName))</c>,
/// for example:
/// <code>
/// "TrustChainValidatorOptions": {
///   "MaxChainLength": null,
///   "Communities": [
///     { "Community": "urn:oid:2.16.840.1.113883.3.7204.1.5", "MaxChainLength": 3 }
///   ]
/// }
/// </code>
/// When <see cref="TrustChainValidator"/> is resolved from dependency injection and options are registered,
/// the current value is read on every validation, so changes made through <c>IOptionsMonitor</c> take effect
/// without a restart.
/// </remarks>
public class TrustChainValidatorOptions
{
    /// <summary>
    /// The configuration section name conventionally used to bind these options.
    /// </summary>
    public const string SectionName = "TrustChainValidatorOptions";

    /// <summary>
    /// Maximum number of certificates allowed in a validated chain, counting the end-entity certificate and the
    /// trust anchor. For example, a framework that fixes the chain to root, intermediate and leaf uses 3.
    /// Applies to every community without its own <see cref="CommunityChainPolicy.MaxChainLength"/> in
    /// <see cref="Communities"/>. <c>null</c> (the default) or a value of 0 or less means no limit.
    /// </summary>
    public int? MaxChainLength { get; set; }

    /// <summary>
    /// Per-community chain policy. An entry whose <see cref="CommunityChainPolicy.MaxChainLength"/> is set
    /// overrides <see cref="MaxChainLength"/> for that community.
    /// </summary>
    public List<CommunityChainPolicy> Communities { get; set; } = new();

    /// <summary>
    /// Returns the chain-length limit that applies to <paramref name="communityName"/>, or <c>null</c> when the
    /// chain length is not limited.
    /// </summary>
    /// <param name="communityName">The community the chain was validated for, or <c>null</c> when not known.</param>
    public int? GetMaxChainLength(string? communityName)
    {
        int? limit = MaxChainLength;

        if (!string.IsNullOrEmpty(communityName))
        {
            var communityLimit = Communities
                .FirstOrDefault(c => c.MaxChainLength.HasValue && string.Equals(c.Community, communityName, StringComparison.Ordinal))
                ?.MaxChainLength;

            if (communityLimit.HasValue)
            {
                limit = communityLimit;
            }
        }

        return limit is > 0 ? limit : null;
    }

    /// <summary>
    /// <c>true</c> when at least one community has its own chain-length limit. Callers that do not already know
    /// the community can skip looking it up when this is <c>false</c>.
    /// </summary>
    public bool HasCommunityLimits => Communities.Any(c => c.MaxChainLength.HasValue);
}

/// <summary>
/// Chain policy for one community, part of <see cref="TrustChainValidatorOptions.Communities"/>.
/// </summary>
public class CommunityChainPolicy
{
    /// <summary>
    /// The community name (URI), for example <c>urn:oid:2.16.840.1.113883.3.7204.1.5</c>.
    /// Compared case-sensitively with the community of the trust anchor the chain is validated against.
    /// </summary>
    public string Community { get; set; } = string.Empty;

    /// <summary>
    /// Maximum number of certificates allowed in the chain for this community, counting the end-entity certificate
    /// and the trust anchor. Overrides <see cref="TrustChainValidatorOptions.MaxChainLength"/>; a value of 0 or less
    /// turns the limit off for this community. <c>null</c> falls back to
    /// <see cref="TrustChainValidatorOptions.MaxChainLength"/>.
    /// </summary>
    public int? MaxChainLength { get; set; }
}
