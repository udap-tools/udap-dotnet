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


using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;

namespace Udap.Common.Extensions
{
    public static class X509Extensions
    {
        /// <summary>
        /// Performs a shallow clone or the specified <see cref="X509ChainPolicy"/>
        /// </summary>
        /// <param name="policy">The instance to clone.</param>
        /// <returns>The shallow cloned instance.</returns>
        public static X509ChainPolicy Clone(this X509ChainPolicy policy)
        {
            X509ChainPolicy newPolicy = new X509ChainPolicy();
            newPolicy.ApplicationPolicy.Add(policy.ApplicationPolicy);
            newPolicy.CertificatePolicy.Add(policy.CertificatePolicy);
            newPolicy.ExtraStore.Add(policy.ExtraStore);
            newPolicy.RevocationFlag = policy.RevocationFlag;
            newPolicy.RevocationMode = policy.RevocationMode;
            newPolicy.UrlRetrievalTimeout = policy.UrlRetrievalTimeout;
            newPolicy.VerificationFlags = policy.VerificationFlags;

            return newPolicy;
        }

        /// <summary>
        /// Adds a collection of <see cref="Oid"/> instances to this collection.
        /// </summary>
        /// <param name="oids">The collection to which to add values</param>
        /// <param name="newOids">The collection to add from</param>
        public static void Add(this OidCollection oids, OidCollection newOids)
        {
            if (newOids == null)
            {
                throw new ArgumentNullException(nameof(newOids));
            }

            for (int i = 0, count = newOids.Count; i < count; ++i)
            {
                oids.Add(newOids[i]);
            }
        }

        /// <summary>
        /// Adds certificates from the supplied collection to this collection.
        /// </summary>
        /// <param name="certs">The collection to which to add certificates.</param>
        /// <param name="newCerts">The collection from which to add certificates.</param>
        public static void Add(this X509Certificate2Collection certs, X509Certificate2Collection? newCerts)
        {
            if (newCerts == null)
            {
                throw new ArgumentNullException(nameof(newCerts));
            }

            foreach (var cert in newCerts)
            {
                certs.Add(cert);
            }
        }

        /// <summary>
        /// Supplies an enumeration for this collection.
        /// </summary>
        /// <param name="certs">The collection to enumerate.</param>
        /// <returns>The enumerator for this collection.</returns>
        public static IEnumerable<X509Certificate2> Enumerate(this X509Certificate2Collection certs)
        {
            return certs.Enumerate(null);
        }

        /// <summary>
        /// Supplies an filtered enumeration for this collection.
        /// </summary>
        /// <param name="certs">The collection to enumerate.</param>
        /// <param name="filter">The filter testing each element of the source collection for enumeration. Elements for which the filter returns <c>false</c> will not be returned by the enumerator.</param>
        /// <returns>The enumerator for this collection.</returns>
        public static IEnumerable<X509Certificate2> Enumerate(this X509Certificate2Collection certs, Predicate<X509Certificate2>? filter)
        {
            foreach (X509Certificate2 cert in certs)
            {
                if (filter == null || filter(cert))
                {
                    yield return cert;
                }
            }
        }

        /// <summary>
        /// Return the first matching element whose certificate thumbprint matches the supplied <paramref name="thumbprint"/>
        /// </summary>
        /// <param name="certs">The source collection to test.</param>
        /// <param name="thumbprint">The certificate thumbprint, as a string, to test against the source collection</param>
        /// <returns>The first matching element, or <c>null</c> if no matching elements are found.</returns>
        public static X509Certificate2? FindByThumbprint(this X509Certificate2Collection certs, string? thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException("value was null or empty", nameof(thumbprint));
            }
            
            return certs.Find(x => x.Thumbprint == thumbprint);
        }

        /// <summary>
        /// Returns the first element matching the supplied predicate.
        /// </summary>
        /// <param name="certs">The source collection to test.</param>
        /// <param name="matcher">The matching predicate for which the first matching element will be returned.</param>
        /// <returns>The first matching element, or <c>null</c> if no matching elements are found.</returns>
        public static X509Certificate2? Find(this X509Certificate2Collection certs, Predicate<X509Certificate2> matcher)
        {
            int index = certs.IndexOf(matcher);

            if (index >= 0)
            {
                return certs[index];
            }

            return null;
        }

        /// <summary>
        /// Returns the index of the first certificate matching the supplied <paramref name="matcher"/>.
        /// </summary>
        /// <param name="certs">The source collection to test.</param>
        /// <param name="matcher">The matching predicate for which the index of the first matching element will be returned.</param>
        /// <returns>The zero-based index of the first matching element, or -1 if no matching elements are found</returns>
        public static int IndexOf(this X509Certificate2Collection certs, Predicate<X509Certificate2> matcher)
        {
            if (matcher == null)
            {
                throw new ArgumentNullException(nameof(matcher));
            }

            for (int i = 0, count = certs.Count; i < count; ++i)
            {
                if (matcher(certs[i]))
                {
                    return i;
                }
            }

            return -1;
        }

        [DebuggerStepThrough]
        public static X509Certificate2Collection? ToX509Collection(this X509Certificate2[] source)
        {
            if (!source.Any())
            {
                return null;
            }

            var x509Coll = new X509Certificate2Collection();

            foreach (var cert in source)
            {
                x509Coll.Add(cert);
            }

            return x509Coll;
        }

        public static string Summarize(this X509ChainStatus[] chainStatuses, X509ChainStatusFlags problemFlags)
        {           
            var builder = new StringBuilder();
            
            
            foreach (var status in chainStatuses)
            {
                if ((status.Status & problemFlags) != 0)
                {
                    builder.Append($"({status.Status}) {status.StatusInformation}");
                    builder.Append(" : ");
                }
            }

            return builder.ToString();
        }

        public static string ToPemFormat(this X509Certificate2 cert)
        {
            var pem = new StringBuilder();
            pem.AppendLine("-----BEGIN CERTIFICATE-----");
            pem.AppendLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
            pem.AppendLine("-----END CERTIFICATE-----");
            return pem.ToString();
        }

        /// <summary>
        /// Gets the specified certificate extension field from the certificate as a <see cref="DerObjectIdentifier"/>.  
        /// The extension field is determined by the oid parameter />
        /// <param name="cert">The certificate to extract the extension field from.</param>
        /// <returns>The extension field as DerObjectIdentifier.  If the extension does not exist in the certificate, then null is returned. </returns>
        /// </summary>
        public static Asn1Object? GetExtensionValue(this X509Certificate2 cert, string oid)
        {
            var x509Extension = cert.Extensions[oid];

            if (x509Extension != null)
            {
                var bytes = x509Extension.RawData;
                if (bytes == null)
                {
                    return null;
                }

                return GetObject(bytes);
            }
            return null;
        }

        /// <summary>
        /// Converts an encoded internal octet string object to a DERObject
        /// </summary>
        /// <param name="ext">The encoded octet string as a byte array</param>
        /// <returns>The converted Asn1Object (DERObject)</returns>
        private static Asn1Object GetObject(byte[] ext)
        {
            Asn1InputStream aIn;

            using (aIn = new Asn1InputStream(ext))
            {
                var octets = aIn.ReadObject();
                Asn1InputStream aInDerEncoded;
                using (aInDerEncoded = new Asn1InputStream(octets.GetDerEncoded()))
                {
                    return aInDerEncoded.ReadObject();
                }
            }
        }
    }
}
