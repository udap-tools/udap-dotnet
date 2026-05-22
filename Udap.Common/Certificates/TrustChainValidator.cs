#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

/*

Author: Joseph.Shook@Surescripts.com

Portions of this code come from Direct Project

 Copyright (c) 2010, Direct Project
 All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
Neither the name of The Direct Project (directproject.org) nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Udap.Common.Models;
using Udap.Util.Extensions;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using BcX509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace Udap.Common.Certificates
{
    /// <summary>
    /// Validates X.509 certificate chains against trusted anchors using BouncyCastle.
    /// Supports CRL revocation checking, AIA certificate chasing, and configurable problem flags.
    /// </summary>
    public class TrustChainValidator
    {
        private readonly ChainProblemStatus _problemFlags;
        private readonly bool _checkRevocation;
        private readonly ICertificateDownloadCache? _downloadCache;
        private readonly HttpClient? _httpClient;
        private readonly ILogger<TrustChainValidator> _logger;
        private readonly TimeSpan _downloadTimeout;
        private const int MaxChainDepth = 10;
        private bool _noCacheWarningLogged;

        /// <summary>
        /// Default timeout for individual CRL and AIA download requests.
        /// </summary>
        public static readonly TimeSpan DefaultDownloadTimeout = TimeSpan.FromSeconds(15);

        /// <summary>
        /// Event fired when a certificate is untrusted
        /// </summary>
        public event Action<X509Certificate2>? Untrusted;

        /// <summary>
        /// Event fired if a certificate has a problem.
        /// </summary>
        public event Action<ChainElementInfo>? Problem;

        /// <summary>
        /// Event fired if there was an error during certificate validation
        /// </summary>
        public event Action<X509Certificate2, Exception>? Error;

        /// <summary>
        /// Default <see cref="ChainProblemStatus"/> flags for validation
        /// </summary>
        public static readonly ChainProblemStatus DefaultProblemFlags =
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.Revoked |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints |
            ChainProblemStatus.OfflineRevocation |
            ChainProblemStatus.RevocationStatusUnknown;

        /// <summary>
        /// Creates an instance with default problem flags and online revocation checking.
        /// When no <see cref="ICertificateDownloadCache"/> is registered, a default HttpClient
        /// is created for direct CRL/AIA downloads.
        /// </summary>
        public TrustChainValidator(
            ILogger<TrustChainValidator> logger,
            ICertificateDownloadCache? downloadCache = null)
            : this(DefaultProblemFlags, true, logger, downloadCache, downloadCache == null ? new HttpClient() : null)
        {
        }

        /// <summary>
        /// Creates an instance with custom problem flags and revocation settings.
        /// No automatic HttpClient is created; CRL/AIA downloads require either a
        /// <see cref="ICertificateDownloadCache"/> or an explicit HttpClient via the 5-parameter constructor.
        /// </summary>
        public TrustChainValidator(
            ChainProblemStatus problemFlags,
            bool checkRevocation,
            ILogger<TrustChainValidator> logger,
            ICertificateDownloadCache? downloadCache = null)
            : this(problemFlags, checkRevocation, logger, downloadCache, null)
        {
        }

        /// <summary>
        /// Creates an instance with custom problem flags, revocation settings, and an optional HttpClient
        /// for direct CRL/AIA downloads when no <see cref="ICertificateDownloadCache"/> is registered.
        /// </summary>
        public TrustChainValidator(
            ChainProblemStatus problemFlags,
            bool checkRevocation,
            ILogger<TrustChainValidator> logger,
            ICertificateDownloadCache? downloadCache,
            HttpClient? httpClient)
            : this(problemFlags, checkRevocation, logger, downloadCache, httpClient, DefaultDownloadTimeout)
        {
        }

        /// <summary>
        /// Creates an instance with custom problem flags, revocation settings, an optional HttpClient,
        /// and a per-request download timeout for CRL and AIA fetches.
        /// </summary>
        public TrustChainValidator(
            ChainProblemStatus problemFlags,
            bool checkRevocation,
            ILogger<TrustChainValidator> logger,
            ICertificateDownloadCache? downloadCache,
            HttpClient? httpClient,
            TimeSpan downloadTimeout)
        {
            _problemFlags = problemFlags;
            _checkRevocation = checkRevocation;
            _logger = logger;
            _downloadCache = downloadCache;
            _httpClient = httpClient;
            _downloadTimeout = downloadTimeout;
        }

        /// <summary>
        /// Validates whether the specified certificate is trusted by building and verifying a chain
        /// against the provided anchor certificates.
        /// </summary>
        /// <param name="clientName">A display name for the client, used in log messages.</param>
        /// <param name="certificate">The end-entity certificate to validate.</param>
        /// <param name="intermediateCertificates">Optional intermediate certificates to include in chain building.</param>
        /// <param name="anchorCertificates">The trust anchor (root CA) certificates to validate against.</param>
        /// <returns><c>true</c> if the certificate chain is valid and trusted; otherwise <c>false</c>.</returns>
        public async Task<bool> IsTrustedCertificateAsync(
            string clientName,
            X509Certificate2 certificate,
            X509Certificate2Collection? intermediateCertificates,
            X509Certificate2Collection anchorCertificates)
        {
            var result = await IsTrustedCertificateAsync(
                clientName,
                certificate,
                intermediateCertificates,
                anchorCertificates,
                null);

            return result.IsValid;
        }

        /// <summary>
        /// Validates whether the specified certificate is trusted, returning detailed chain element
        /// information and an optional community identifier from the matching anchor.
        /// </summary>
        /// <param name="clientName">A display name for the client, used in log messages.</param>
        /// <param name="certificate">The end-entity certificate to validate.</param>
        /// <param name="intermediateCertificates">Optional intermediate certificates to include in chain building.</param>
        /// <param name="anchorCertificates">The trust anchor (root CA) certificates to validate against.</param>
        /// <param name="anchors">Optional <see cref="Anchor"/> models to resolve a <see cref="ChainValidationResult.CommunityId"/>.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A <see cref="ChainValidationResult"/> containing the validation outcome, chain elements, and community identifier.</returns>
        public async Task<ChainValidationResult> IsTrustedCertificateAsync(
            string clientName,
            X509Certificate2 certificate,
            X509Certificate2Collection? intermediateCertificates,
            X509Certificate2Collection anchorCertificates,
            IEnumerable<Anchor>? anchors = null,
            CancellationToken cancellationToken = default)
        {
            var roots = new X509Certificate2Collection(anchorCertificates);
            X509Certificate2Collection? intermediatesCloned = null;

            if (intermediateCertificates != null)
            {
                intermediatesCloned = new X509Certificate2Collection(intermediateCertificates);
            }

            if (roots.IsNullOrEmpty())
            {
                NotifyUntrusted(certificate);
                return new ChainValidationResult(false, Array.Empty<ChainElementInfo>());
            }

            try
            {
                var parser = new X509CertificateParser();
                var bcLeaf = parser.ReadCertificate(certificate.RawData);

                // Convert anchors to BouncyCastle
                var bcAnchors = new List<BcX509Certificate>();
                foreach (X509Certificate2 anchor in roots)
                {
                    bcAnchors.Add(parser.ReadCertificate(anchor.RawData));
                }

                // Convert intermediates to BouncyCastle
                var bcIntermediates = new List<BcX509Certificate>();
                if (intermediatesCloned != null)
                {
                    foreach (X509Certificate2 intermediate in intermediatesCloned)
                    {
                        bcIntermediates.Add(parser.ReadCertificate(intermediate.RawData));
                    }
                }

                // Build the chain
                var bcChain = await BuildChainAsync(bcLeaf, bcIntermediates, bcAnchors, cancellationToken);

                // Map back to .NET certs and build chain element info
                var chainElements = new List<ChainElementInfo>();
                bool foundAnchor = false;
                long? communityId = null;
                string? communityName = null;
                bool chainValid = true;

                for (int i = 0; i < bcChain.Count; i++)
                {
                    var bcCert = bcChain[i];
                    var dotNetCert = FindMatchingDotNetCert(bcCert, certificate, roots, intermediatesCloned);
                    var problems = new List<ChainProblem>();

                    // Check time validity
                    if (!IsCertTimeValid(bcCert))
                    {
                        problems.Add(new ChainProblem(
                            ChainProblemStatus.NotTimeValid,
                            $"Certificate is not valid. NotBefore: {bcCert.NotBefore}, NotAfter: {bcCert.NotAfter}"));
                    }

                    // Signature verification is done during chain building, so we just check
                    // for revocation and basic constraints here.

                    // Check basic constraints for intermediate certs (not leaf, not anchor)
                    bool isAnchor = IsAnchor(bcCert, bcAnchors);
                    bool isLeaf = i == 0;

                    if (!isLeaf && !isAnchor)
                    {
                        if (!HasValidBasicConstraints(bcCert))
                        {
                            problems.Add(new ChainProblem(
                                ChainProblemStatus.InvalidBasicConstraints,
                                "Certificate does not have valid CA basic constraints"));
                        }
                    }

                    // Check CRL revocation (skip for anchor/root)
                    if (_checkRevocation && !isAnchor)
                    {
                        var revocationResult = await CheckRevocationAsync(bcCert, bcChain, i, cancellationToken);
                        problems.AddRange(revocationResult);
                    }

                    if (isAnchor)
                    {
                        foundAnchor = true;
                        var anchorList = (anchors ?? Array.Empty<Anchor>()).ToList();

                        if (anchorList.Count != 0 && dotNetCert != null)
                        {
                            var matchingAnchor = anchorList.FirstOrDefault(a => a.Thumbprint == dotNetCert.Thumbprint);
                            if (matchingAnchor != null)
                            {
                                communityId = matchingAnchor.CommunityId;
                                communityName = matchingAnchor.Community;
                            }
                        }
                    }

#if NET9_0_OR_GREATER
                    var element = new ChainElementInfo(dotNetCert ?? X509CertificateLoader.LoadCertificate(bcCert.GetEncoded()), problems);
#else
                    var element = new ChainElementInfo(dotNetCert ?? new X509Certificate2(bcCert.GetEncoded()), problems);
#endif
                    chainElements.Add(element);

                    // Check if this element has problems we care about
                    if (HasRelevantProblems(problems))
                    {
                        NotifyProblem(element);
                        chainValid = false;
                    }
                }

                _logger.LogDebug(string.Join(",", chainElements
                    .Select(ce =>
                        $"{Environment.NewLine}{ce.Certificate.Thumbprint} :: " +
                        $"CN = {ce.Certificate.GetNameInfo(X509NameType.SimpleName, false)}")));

                if (!foundAnchor)
                {
                    NotifyUntrusted(certificate);
                    return new ChainValidationResult(false, chainElements);
                }

                if (!chainValid)
                {
                    _logger.LogWarning(
                        "Client: {ClientName} Problem Flags set: {ProblemFlags} ChainStatus: {ChainStatus}",
                        clientName,
                        _problemFlags.ToString(),
                        string.Join(", ", chainElements
                            .SelectMany(e => e.Problems)
                            .Select(p => $"({p.Status}) {p.StatusInformation}")));
                }

                bool isValid = chainValid && foundAnchor;

                if (!isValid)
                {
                    NotifyUntrusted(certificate);
                }

                return new ChainValidationResult(isValid, chainElements, communityId, communityName);
            }
            catch (Exception ex)
            {
                NotifyError(certificate, ex);
            }

            NotifyUntrusted(certificate);
            return new ChainValidationResult(false, Array.Empty<ChainElementInfo>());
        }

        private async Task<List<BcX509Certificate>> BuildChainAsync(
            BcX509Certificate leaf,
            List<BcX509Certificate> intermediates,
            List<BcX509Certificate> anchors,
            CancellationToken cancellationToken)
        {
            var chain = new List<BcX509Certificate> { leaf };
            var current = leaf;
            var visited = new HashSet<string> { GetThumbprint(leaf) };

            for (int depth = 0; depth < MaxChainDepth; depth++)
            {
                // Check if current cert is self-signed (root)
                if (current.IssuerDN.Equivalent(current.SubjectDN))
                {
                    try
                    {
                        current.Verify(current.GetPublicKey());
                        break; // Self-signed and valid signature = root
                    }
                    catch (Exception ex)
                    {
                        // Not actually self-signed (subject/issuer match but sig fails)
                        _logger.LogDebug(ex, "Subject/Issuer DN match but self-signature verification failed for {Subject}", current.SubjectDN);
                    }
                }

                // Look for issuer in anchors first
                var issuer = FindIssuer(current, anchors);

                if (issuer != null)
                {
                    chain.Add(issuer);
                    break; // Reached a trust anchor
                }

                // Look for issuer in provided intermediates
                issuer = FindIssuer(current, intermediates);

                // If not found, try AIA chasing
                if (issuer == null && (_downloadCache != null || _httpClient != null))
                {
                    issuer = await ChaseAiaAsync(current, cancellationToken);

                    if (issuer != null)
                    {
                        // Add to intermediates so it's available for CRL issuer lookups
                        intermediates.Add(issuer);
                    }
                }

                if (issuer == null)
                {
                    _logger.LogWarning("Could not find issuer for certificate: {Subject}", current.SubjectDN);
                    break; // Can't continue the chain
                }

                var issuerThumbprint = GetThumbprint(issuer);
                if (visited.Contains(issuerThumbprint))
                {
                    _logger.LogWarning("Loop detected in certificate chain at: {Subject}", issuer.SubjectDN);
                    break;
                }

                visited.Add(issuerThumbprint);
                chain.Add(issuer);
                current = issuer;
            }

            return chain;
        }

        private BcX509Certificate? FindIssuer(BcX509Certificate cert, List<BcX509Certificate> candidates)
        {
            foreach (var candidate in candidates)
            {
                if (!cert.IssuerDN.Equivalent(candidate.SubjectDN))
                {
                    continue;
                }

                // Verify Authority Key Identifier matches Subject Key Identifier if both present
                if (!MatchesKeyIdentifiers(cert, candidate))
                {
                    continue;
                }

                try
                {
                    cert.Verify(candidate.GetPublicKey());
                    return candidate;
                }
                catch (SignatureException)
                {
                    _logger.LogDebug(
                        "DN match but signature verification failed: {Issuer} -> {Subject}",
                        candidate.SubjectDN, cert.SubjectDN);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex,
                        "Error verifying signature for {Subject} against {Issuer}",
                        cert.SubjectDN, candidate.SubjectDN);
                }
            }

            return null;
        }

        private static bool MatchesKeyIdentifiers(BcX509Certificate cert, BcX509Certificate issuer)
        {
            try
            {
                var akiValue = cert.GetExtensionValue(BcX509Extensions.AuthorityKeyIdentifier);
                var skiValue = issuer.GetExtensionValue(BcX509Extensions.SubjectKeyIdentifier);

                if (akiValue == null || skiValue == null)
                {
                    return true; // Can't compare, allow DN match to be sufficient
                }

                var aki = AuthorityKeyIdentifier.GetInstance(
                    Asn1OctetString.GetInstance(akiValue).GetOctets());
                var ski = SubjectKeyIdentifier.GetInstance(
                    Asn1OctetString.GetInstance(skiValue).GetOctets());

                return aki.GetKeyIdentifier().SequenceEqual(ski.GetKeyIdentifier());
            }
            catch
            {
                return true; // If we can't parse extensions, allow DN match
            }
        }

        private async Task<BcX509Certificate?> ChaseAiaAsync(
            BcX509Certificate cert,
            CancellationToken cancellationToken)
        {
            var aiaValue = cert.GetExtensionValue(BcX509Extensions.AuthorityInfoAccess);
            if (aiaValue == null)
            {
                return null;
            }

            try
            {
                var aia = AuthorityInformationAccess.GetInstance(
                    Asn1OctetString.GetInstance(aiaValue).GetOctets());

                foreach (var accessDescription in aia.GetAccessDescriptions())
                {
                    if (!accessDescription.AccessMethod.Equals(AccessDescription.IdADCAIssuers))
                    {
                        continue;
                    }

                    var location = accessDescription.AccessLocation;
                    if (location.TagNo != GeneralName.UniformResourceIdentifier)
                    {
                        continue;
                    }

                    var url = location.Name.ToString();
                    if (string.IsNullOrEmpty(url))
                    {
                        continue;
                    }

                    _logger.LogDebug("AIA chasing intermediate from {Url}", url);

                    var intermediateCert = await DownloadIntermediateCertificateAsync(url, cancellationToken);
                    if (intermediateCert != null)
                    {
                        var parser = new X509CertificateParser();
                        var bcIntermediate = parser.ReadCertificate(intermediateCert.RawData);

                        // Verify this is actually the issuer
                        try
                        {
                            cert.Verify(bcIntermediate.GetPublicKey());
                            return bcIntermediate;
                        }
                        catch
                        {
                            _logger.LogWarning("AIA-fetched certificate from {Url} did not verify as issuer", url);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error parsing AIA extension");
            }

            return null;
        }

        private async Task<X509Certificate2?> DownloadIntermediateCertificateAsync(
            string url, CancellationToken cancellationToken)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_downloadTimeout);

            if (_downloadCache != null)
            {
                return await _downloadCache.GetIntermediateCertificateAsync(url, timeoutCts.Token);
            }

            LogNoCacheWarning();

            try
            {
                var data = await _httpClient!.GetByteArrayAsync(url, timeoutCts.Token);
#if NET9_0_OR_GREATER
                return X509CertificateLoader.LoadCertificate(data);
#else
                return new X509Certificate2(data);
#endif
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to download intermediate certificate from {Url}", url);
                return null;
            }
        }

        private async Task<X509Crl?> DownloadCrlAsync(
            string url, CancellationToken cancellationToken)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_downloadTimeout);

            if (_downloadCache != null)
            {
                return await _downloadCache.GetCrlAsync(url, timeoutCts.Token);
            }

            if (_httpClient == null)
            {
                _logger.LogWarning("No download cache or HttpClient available to download CRL from {Url}", url);
                return null;
            }

            LogNoCacheWarning();

            try
            {
                var data = await _httpClient.GetByteArrayAsync(url, timeoutCts.Token);
                return new X509CrlParser().ReadCrl(data);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to download CRL from {Url}", url);
                return null;
            }
        }

        private void LogNoCacheWarning()
        {
            if (!_noCacheWarningLogged)
            {
                _logger.LogWarning(
                    "No ICertificateDownloadCache is configured. CRL and AIA downloads will not be cached, " +
                    "which may impact performance. Consider registering an ICertificateDownloadCache implementation.");
                _noCacheWarningLogged = true;
            }
        }

        private async Task<List<ChainProblem>> CheckRevocationAsync(
            BcX509Certificate cert,
            List<BcX509Certificate> chain,
            int certIndex,
            CancellationToken cancellationToken)
        {
            var problems = new List<ChainProblem>();

            var crlDpValue = cert.GetExtensionValue(BcX509Extensions.CrlDistributionPoints);
            if (crlDpValue == null)
            {
                if ((_problemFlags & ChainProblemStatus.OfflineRevocation) != 0)
                {
                    problems.Add(new ChainProblem(
                        ChainProblemStatus.CrlNotFound,
                        "Certificate does not contain CRL Distribution Point extension"));
                }
                return problems;
            }

            var crlChecked = false;
            var now = DateTime.UtcNow;

            try
            {
                var crlDistPoint = CrlDistPoint.GetInstance(
                    Asn1OctetString.GetInstance(crlDpValue).GetOctets());

                foreach (var dp in crlDistPoint.GetDistributionPoints())
                {
                    var dpName = dp.DistributionPointName;
                    if (dpName?.Type != DistributionPointName.FullName)
                    {
                        continue;
                    }

                    var generalNames = GeneralNames.GetInstance(dpName.Name);
                    foreach (var name in generalNames.GetNames())
                    {
                        if (name.TagNo != GeneralName.UniformResourceIdentifier)
                        {
                            continue;
                        }

                        var url = name.Name.ToString();
                        if (string.IsNullOrEmpty(url))
                        {
                            continue;
                        }

                        // Only allow http/https schemes for CRL downloads
                        if (!Uri.TryCreate(url, UriKind.Absolute, out var crlUri) ||
                            (crlUri.Scheme != Uri.UriSchemeHttp && crlUri.Scheme != Uri.UriSchemeHttps))
                        {
                            _logger.LogDebug("Skipping CRL DP with unsupported URI scheme: {Url}", url);
                            continue;
                        }

                        var crl = await DownloadCrlAsync(url, cancellationToken);

                        if (crl == null)
                        {
                            problems.Add(new ChainProblem(
                                ChainProblemStatus.CrlFetchFailed,
                                $"Failed to download CRL from {url}"));
                            continue;
                        }

                        // Verify CRL is signed by the issuer
                        if (certIndex + 1 < chain.Count)
                        {
                            var issuer = chain[certIndex + 1];
                            try
                            {
                                crl.Verify(issuer.GetPublicKey());
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "CRL from {Url} failed signature verification against expected issuer", url);
                                continue;
                            }
                        }

                        // Check if ThisUpdate is in the future (clock skew or bad CRL)
                        if (crl.ThisUpdate.ToUniversalTime() > now)
                        {
                            _logger.LogWarning("CRL from {Url} has ThisUpdate in the future ({ThisUpdate}), treating as unknown", url, crl.ThisUpdate);
                            problems.Add(new ChainProblem(
                                ChainProblemStatus.RevocationStatusUnknown,
                                $"CRL from {url} has ThisUpdate in the future ({crl.ThisUpdate:O})"));
                            continue;
                        }

                        // Check if the CRL has expired (NextUpdate has passed)
                        if (crl.NextUpdate != null && crl.NextUpdate.Value.ToUniversalTime() < now)
                        {
                            _logger.LogWarning("CRL from {Url} has expired (NextUpdate: {NextUpdate})", url, crl.NextUpdate.Value);

                            // Evict the stale CRL from cache so a fresh one is fetched next time
                            if (_downloadCache != null)
                            {
                                await _downloadCache.RemoveCrlAsync(url, cancellationToken);
                            }

                            problems.Add(new ChainProblem(
                                ChainProblemStatus.RevocationStatusUnknown,
                                $"CRL from {url} has expired (NextUpdate: {crl.NextUpdate.Value:O})"));
                            continue;
                        }

                        if (crl.IsRevoked(cert))
                        {
                            problems.Add(new ChainProblem(
                                ChainProblemStatus.Revoked,
                                $"Certificate is revoked per CRL at {url}"));
                        }

                        crlChecked = true;

                        // Stop after first successful CRL check. UDAP PKI does not use
                        // partitioned CRLs, so a single DP is sufficient. If a Revoked
                        // status was found above, it was already recorded. For PKIs with
                        // partitioned CRLs, this would need to continue checking remaining DPs.
                        break;
                    }

                    if (crlChecked)
                    {
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking CRL revocation");
                problems.Add(new ChainProblem(
                    ChainProblemStatus.CrlFetchFailed,
                    $"Error checking CRL: {ex.Message}"));
            }

            if (!crlChecked)
            {
                if ((_problemFlags & ChainProblemStatus.OfflineRevocation) != 0)
                {
                    problems.Add(new ChainProblem(
                        ChainProblemStatus.OfflineRevocation,
                        "Revocation checking failed: no CRL could be retrieved or verified"));
                }

                if ((_problemFlags & ChainProblemStatus.RevocationStatusUnknown) != 0
                    && !problems.Any(p => p.Status == ChainProblemStatus.RevocationStatusUnknown))
                {
                    problems.Add(new ChainProblem(
                        ChainProblemStatus.RevocationStatusUnknown,
                        "Revocation status could not be determined: no CRL was successfully checked"));
                }
            }

            return problems;
        }

        private static bool IsCertTimeValid(BcX509Certificate cert)
        {
            var now = DateTime.UtcNow;
            return now >= cert.NotBefore && now <= cert.NotAfter;
        }

        private static bool HasValidBasicConstraints(BcX509Certificate cert)
        {
            var basicConstraints = cert.GetBasicConstraints();
            // GetBasicConstraints returns -1 if not a CA, or pathLen (>= 0) if CA
            return basicConstraints >= 0;
        }

        private static bool IsAnchor(BcX509Certificate cert, List<BcX509Certificate> anchors)
        {
            var certThumbprint = GetThumbprint(cert);
            return anchors.Any(a => GetThumbprint(a) == certThumbprint);
        }

        private static string GetThumbprint(BcX509Certificate cert)
        {
            return Convert.ToHexString(
                System.Security.Cryptography.SHA1.HashData(cert.GetEncoded()));
        }

        private static X509Certificate2? FindMatchingDotNetCert(
            BcX509Certificate bcCert,
            X509Certificate2 leafCert,
            X509Certificate2Collection anchors,
            X509Certificate2Collection? intermediates)
        {
            var bcThumbprint = GetThumbprint(bcCert);

            if (leafCert.Thumbprint.Equals(bcThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                return leafCert;
            }

            foreach (X509Certificate2 anchor in anchors)
            {
                if (anchor.Thumbprint.Equals(bcThumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    return anchor;
                }
            }

            if (intermediates != null)
            {
                foreach (X509Certificate2 intermediate in intermediates)
                {
                    if (intermediate.Thumbprint.Equals(bcThumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return intermediate;
                    }
                }
            }

            return null;
        }

        private bool HasRelevantProblems(List<ChainProblem> problems)
        {
            return problems.Any(p => (_problemFlags & p.Status) != 0);
        }

        private void NotifyUntrusted(X509Certificate2 cert)
        {
            _logger.LogWarning("{Validator} Untrusted: {CertificateSubject}", nameof(TrustChainValidator), cert.Subject);

            if (Untrusted != null)
            {
                try
                {
                    Untrusted(cert);
                }
                catch
                {
                    // ignored
                }
            }
        }

        private void NotifyProblem(ChainElementInfo chainElement)
        {
            _logger.LogWarning("{Validator} {Subject} Chain Problem: {Problems}",
                nameof(TrustChainValidator),
                chainElement.Certificate.Subject,
                string.Join(", ", chainElement.Problems.Select(p => $"({p.Status}) {p.StatusInformation}")));

            if (Problem != null)
            {
                try
                {
                    Problem(chainElement);
                }
                catch
                {
                    // ignored
                }
            }
        }

        private void NotifyError(X509Certificate2 cert, Exception exception)
        {
            _logger.LogWarning("{Validator} Error: {ErrorMessage}", nameof(TrustChainValidator), exception.Message);

            if (Error != null)
            {
                try
                {
                    Error(cert, exception);
                }
                catch
                {
                    // ignored
                }
            }
        }
    }
}
