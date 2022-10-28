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
using Udap.Common.Extensions;
#if !NET5_0_OR_GREATER && !Linux
using Udap.Custom.TrustStore;
#endif

namespace Udap.Common.Certificates
{
    // TODO:
    // Notes:   Follow up on this https://stackoverflow.com/questions/59382619/online-revocation-checking-using-custom-root-in-x509chain
    //          .NET 6.0 should be able to avoid the UdapWindowStore package.  Only .Net Framework and .Net less than 5.0 will need UdapWindowsStore.
    //
    
    public class TrustChainValidator
    {
        private X509ChainPolicy _validationPolicy;
        private X509ChainStatusFlags _problemFlags;
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
            if (IsNewerThanWin2008R2())
            {
                return X509ChainStatusFlags.NotTimeValid |
                       X509ChainStatusFlags.Revoked |
                       X509ChainStatusFlags.NotSignatureValid |
                       X509ChainStatusFlags.InvalidBasicConstraints |
                       X509ChainStatusFlags.CtlNotTimeValid |
                       X509ChainStatusFlags.OfflineRevocation |
                       X509ChainStatusFlags.CtlNotSignatureValid |
                       X509ChainStatusFlags.RevocationStatusUnknown; // can't trust the chain to even check revocation.
            }

            return X509ChainStatusFlags.NotTimeValid |
                   X509ChainStatusFlags.Revoked |
                   X509ChainStatusFlags.NotSignatureValid |
                   X509ChainStatusFlags.InvalidBasicConstraints |
                   X509ChainStatusFlags.CtlNotTimeValid |
                   X509ChainStatusFlags.CtlNotSignatureValid;
        }

        // X509ChainEngine, which is used for CRL validation, requires Windows 2012 to run due to required changes in the CERT_CHAIN_ENGINE_CONFIG structure.
        // For more information on version numbers, see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832.aspx
        private static bool IsNewerThanWin2008R2()
        {
            return Environment.OSVersion.Version.Major > 6 ||
                   (Environment.OSVersion.Version.Major >= 6 &&
                    Environment.OSVersion.Version.Minor >= 2);
        }

        /// <summary>
        /// Creates an instance with default chain policy, problem flags.
        /// </summary>
        public TrustChainValidator(ILogger<TrustChainValidator> logger)
            : this(new X509ChainPolicy(), BuildDefaultProblemFlags(), logger)
        {
            _validationPolicy.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage;
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
            X509Certificate2 certificate, 
            X509Certificate2Collection? communityTrustAnchors, 
            X509Certificate2Collection? trustedRoots = null)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            // if there are no anchors we should always fail
            if (communityTrustAnchors.IsNullOrEmpty())
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
                // Again more to test here.
                //

                // if (this.HasCertificateResolver)
                // {
                //     this.ResolveIntermediateIssuers(certificate, chainPolicy.ExtraStore);
                // }

                X509Chain chainBuilder;

#if NET5_0_OR_GREATER

                chainBuilder = new X509Chain();
               
                if (!trustedRoots.IsNullOrEmpty())
                {
                    chainPolicy.CustomTrustStore.Clear();
                    chainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chainPolicy.CustomTrustStore.AddRange(trustedRoots);
                }
                
                chainBuilder.ChainPolicy = chainPolicy;
                chainBuilder.ChainPolicy.ExtraStore.AddRange(communityTrustAnchors);
                chainBuilder.Build(certificate);
#else
                if (IsNewerThanWin2008R2())
                {
                    chainBuilder = new X509Chain();
                    //
                    // The state of this code will terminate the chain at the community trust anchor.
                    // The weakness in this is a revoked anchor will not be validated.  At least that I believe that is the case. 
                    // Well I guess if I changed this to include the trustedRoots it would be correct but still if you don't 
                    // it terminates and ignores the CRL.  
                    // I might get rid of all all this complexity.  Just want this history here for now.
                    //
                    using (var secureChainEngine = new X509ChainEngine(communityTrustAnchors?.Enumerate()))
                    {
                        secureChainEngine.BuildChain(certificate, chainPolicy, out chainBuilder);
                    }
                }
                else
                {
                    //
                    // Stuck putting Certificates in the Machine Store other wise Windows will not trust them
                    //
                     chainBuilder = new X509Chain();
                     chainBuilder.ChainPolicy = chainPolicy;
                     chainBuilder.Build(certificate);
                }
#endif


                // We're using the system class as a helper to build the chain
                // However, we will review each item in the chain ourselves, because we have our own rules...
                var chainElements = chainBuilder.ChainElements;

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
                    bool isAnchor = communityTrustAnchors?.FindByThumbprint(chainElement.Certificate.Thumbprint) != null;

                    if (isAnchor)
                    {
                        // Found a valid anchor!
                        // Because we found an anchor we trust, we can skip trust
                        foundAnchor = true;
                        continue;
                    }

                    if (this.ChainElementHasProblems(chainElement))
                    {
                        this.NotifyProblem(chainElement);

                        // Whoops... problem with at least one cert in the chain. Stop immediately
                        return false;
                    }
                }

                return foundAnchor;
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
            X509ChainStatus[] chainElementStatus = chainElement.ChainElementStatus;

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
            _logger.LogWarning($"{nameof(TrustChainValidator)} Untrusted: {cert.Subject}");

            if (this.Untrusted != null)
            {
                try
                {
                    this.Untrusted(cert);
                    
                }
                catch
                {
                }
            }
        }

        private void NotifyProblem(X509ChainElement chainElement)
        {
            _logger.LogWarning($"{nameof(TrustChainValidator)} Chain Problem: {chainElement.ChainElementStatus.Summarize(_problemFlags)}");

            if (this.Problem != null)
            {
                try
                {
                    this.Problem(chainElement);
                }
                catch
                {
                }
            }
        }

        private void NotifyError(X509Certificate2 cert, Exception exception)
        {
            _logger.LogWarning($"{nameof(TrustChainValidator)} Error: {exception.Message}");

            if (this.Error != null)
            {
                try
                {
                    this.Error(cert, exception);
                }
                catch
                {
                }
            }
        }
    }
}
