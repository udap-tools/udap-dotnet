#region (c) 2022 Joseph Shook. All rights reserved.
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
using Udap.Common.Models;
using Udap.Util.Extensions;

namespace Udap.Common.Certificates
{
    public class TrustChainValidator
    {
        private readonly X509ChainPolicy _validationPolicy;
        private readonly X509ChainStatusFlags _problemFlags;
        private const X509RevocationMode DefaultX509RevocationMode = X509RevocationMode.Online;
        private const X509RevocationFlag DefaultX509RevocationFlag = X509RevocationFlag.ExcludeRoot;
        private readonly ILogger<TrustChainValidator> _logger;

        /// <summary>
        /// Event fired when a certificate is untrusted
        /// </summary>
        public event Action<X509Certificate2>? Untrusted;

        /// <summary>
        /// Event fired if a certificate has a problem.
        /// </summary>
        public event Action<X509ChainElement>? Problem;

        /// <summary>
        /// Event fired if there was an error during certificate validation
        /// </summary>
        public event Action<X509Certificate2, Exception>? Error;

        /// <summary>
        /// Default <see cref="X509ChainStatusFlags"/> that we will be validating by default if not supplied by the caller
        /// </summary>
        public static readonly X509ChainStatusFlags DefaultProblemFlags =
            BuildDefaultProblemFlags();

        private static X509ChainStatusFlags BuildDefaultProblemFlags()
        {
            return X509ChainStatusFlags.NotTimeValid |
                   X509ChainStatusFlags.Revoked |
                   X509ChainStatusFlags.NotSignatureValid |
                   X509ChainStatusFlags.InvalidBasicConstraints |
                   X509ChainStatusFlags.CtlNotTimeValid |
                   X509ChainStatusFlags.OfflineRevocation |
                   X509ChainStatusFlags.CtlNotSignatureValid;
        }

        /// <summary>
        /// Creates an instance with default chain policy, problem flags.
        /// </summary>
        public TrustChainValidator(ILogger<TrustChainValidator> logger)
            : this(new X509ChainPolicy(), BuildDefaultProblemFlags(), logger)
        {
            _validationPolicy.VerificationFlags = X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                                  X509VerificationFlags.IgnoreEndRevocationUnknown |
                                                  X509VerificationFlags.AllowUnknownCertificateAuthority |
                                                  X509VerificationFlags.IgnoreWrongUsage;

            _validationPolicy.RevocationFlag = DefaultX509RevocationFlag;
            _validationPolicy.RevocationMode = DefaultX509RevocationMode;
        }

        /// <summary>
        /// Creates an instance with default chain policy, problem flags.
        /// </summary>
        public TrustChainValidator(X509ChainPolicy policy, ILogger<TrustChainValidator> logger)
            : this(policy, BuildDefaultProblemFlags(), logger)
        {
        }

        /// <summary>
        /// Creates an instance, specifying chain policy and problem flags
        /// </summary>
        /// <param name="policy">The <see cref="X509ChainPolicy"/> to use for validating trust chains</param>
        /// <param name="problemFlags">The status flags that will be treated as invalid in trust verification</param>
        /// <param name="logger"></param>
        public TrustChainValidator(X509ChainPolicy policy, X509ChainStatusFlags problemFlags, ILogger<TrustChainValidator> logger)
        {
            _validationPolicy = policy;
            _problemFlags = problemFlags;
            _logger = logger;
        }

        public bool IsTrustedCertificate(
            string clientName,
            X509Certificate2 certificate,
            X509Certificate2Collection? intermediateCertificates,
            X509Certificate2Collection anchorCertificates)
        {
            return IsTrustedCertificate(
                clientName,
                certificate,
                intermediateCertificates,
                anchorCertificates,
                out X509ChainElementCollection? _,
                out _);
        }

        public bool IsTrustedCertificate(string clientName,
            X509Certificate2 certificate,
            X509Certificate2Collection? intermediateCertificates,
            X509Certificate2Collection anchorCertificates,
            out X509ChainElementCollection? chainElements,
            out long? communityId,
            IEnumerable<Anchor>? anchors = null)
        {
            communityId = null;
            chainElements = null;

            // Let's avoid complex state and/or race conditions by making copies of these collections.
            var roots = new X509Certificate2Collection(anchorCertificates);
            X509Certificate2Collection? intermediatesCloned = null;

            if (intermediateCertificates != null)
            {
                intermediatesCloned = new X509Certificate2Collection(intermediateCertificates);
            }

            // ReSharper disable once RedundantAssignment
            intermediateCertificates = null;


            // if there are no anchors we should always fail
            if (roots.IsNullOrEmpty())
            {
                this.NotifyUntrusted(certificate);
                return false;
            }

            try
            {
                var chainPolicy = _validationPolicy.Clone();

                //
                // TODO:
                // The x5c in jwt header can contain a list of intermediates and possibly the anchor or more.
                // Come back to this and set up a use case test and code this up then.
                // In direct world this was just a way to resolve the intermediate in our own store
                // I don't think on Windows we ever did this in practice.
                // The chain builder in Windows and I believe in OpenSSL on Linux does the intermediate resolution.
                // Note: I found if this is hosted on an Android device the intermediate certificate is not automatically
                // resolved by the x509Chain.Build().
                // Again more to test here.
                //

                using var chainBuilder = new X509Chain();

                if (!roots.IsNullOrEmpty())
                {
                    chainPolicy.CustomTrustStore.Clear();
                    chainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chainPolicy.CustomTrustStore.AddRange(roots);
                }

                chainBuilder.ChainPolicy = chainPolicy;
                if (intermediatesCloned != null)
                {
                    chainBuilder.ChainPolicy.ExtraStore.AddRange(intermediatesCloned);
                }
                var passedChainBuild = chainBuilder.Build(certificate);

                // We're using the system class as a helper to build the chain
                // However, we will review each item in the chain ourselves, because we have our own rules...
                chainElements = chainBuilder.ChainElements;

                // If we don't have a trust chain, then we obviously have a problem...
                if (chainElements.IsNullOrEmpty())
                {
                    this.NotifyUntrusted(certificate);
                    return false;
                }

                bool foundAnchor = false;

                // walk the chain starting at the leaf and see if we hit any issues before the anchor
                foreach (var chainElement in chainElements)
                {
                    bool isAnchor = roots?.FindByThumbprint(chainElement.Certificate.Thumbprint) != null;

                    if (isAnchor)
                    {
                        // Found a valid anchor!
                        // Because we found an anchor we trust, we can skip trust
                        foundAnchor = true;
                        var anchorList = (anchors ?? Array.Empty<Anchor>()).ToList();

                        if (anchorList.Count != 0)
                        {
                            communityId = anchorList.First(a => a.Thumbprint == chainElement.Certificate.Thumbprint).CommunityId;
                        }
                    }

                    if (!passedChainBuild && this.ChainElementHasProblems(chainElement))
                    {
                        // chain statuses can still be subscribed too.  There may be data to share with the consumer
                        // that do not mean the chain is invalid.  passedChainBuild is the final arbiter of trust
                        // for a x509Chain.
                        this.NotifyProblem(chainElement);

                        if (!passedChainBuild)
                        {
                            this.NotifyUntrusted(chainElement.Certificate);
                        }

                        if (passedChainBuild && foundAnchor)
                        {
                            return true;
                        }
                    }
                }

                if (foundAnchor && !passedChainBuild)
                {
                    //
                    // Can end up here if problem flags exist that we do not care about.
                    //
                    _logger.LogWarning("Client: {ClientName} Problem Flags set: {ProblemFlags} ChainStatus: {ChainStatus}",
                        clientName,
                        _problemFlags.ToString(),
                        chainElements.Summarize());
                }

                if (!foundAnchor)
                {
                    this.NotifyUntrusted(certificate);
                }

                return passedChainBuild;
            }
            catch (Exception ex)
            {
                this.NotifyError(certificate, ex);
                // just eat it and drop out to return false
            }

            this.NotifyUntrusted(certificate);

            return false;
        }

        private bool ChainElementHasProblems(X509ChainElement chainElement)
        {
            // If the builder finds problems with the cert, it will provide a list of "status" flags for the cert
            var chainElementStatus = chainElement.ChainElementStatus;

            // If the list is empty or the list is null, then there were NO problems with the cert
            if (chainElementStatus.IsNullOrEmpty())
            {
                return false;
            }

            // Return true if there are any status flags we care about
            return chainElementStatus.Any(s => (s.Status & _problemFlags) != 0);
        }


        private void NotifyUntrusted(X509Certificate2 cert)
        {
            _logger.LogWarning("{Validator} Untrusted: {CertificateSubject}", nameof(TrustChainValidator), cert.Subject);

            if (this.Untrusted != null)
            {
                try
                {
                    this.Untrusted(cert);

                }
                catch
                {
                    // ignored
                }
            }
        }

        private void NotifyProblem(X509ChainElement chainElement)
        {
            _logger.LogWarning("{Validator} Chain Problem: {ChainStatus}", nameof(TrustChainValidator), chainElement.ChainElementStatus.Summarize(_problemFlags));

            if (this.Problem != null)
            {
                try
                {
                    this.Problem(chainElement);
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

            if (this.Error != null)
            {
                try
                {
                    this.Error(cert, exception);
                }
                catch
                {
                    // ignored
                }
            }
        }
    }
}
