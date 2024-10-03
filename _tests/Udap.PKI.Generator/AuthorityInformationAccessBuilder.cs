#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Udap.PKI.Generator
{
    public sealed class AuthorityInformationAccessBuilder
    {
        private readonly List<byte[]> _encodedSequences = [];
        /// <summary>
        /// Adding ObjectIdentifier (OID) 1.3.6.1.5.5.7.48.2
        /// </summary>
        /// <param name="uri"></param>
        public void AddCertificateAuthorityIssuerUri(Uri uri)
        {
            var encodedParts = new List<byte[]>();

            ArgumentNullException.ThrowIfNull(uri);
            
            var writer = new AsnWriter(AsnEncodingRules.DER);
            
            writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2"); //Certificate Authority Issuer
            encodedParts.Add(writer.Encode());

            writer = new AsnWriter(AsnEncodingRules.DER);

            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, 
                uri.AbsoluteUri, 
                new Asn1Tag(TagClass.ContextSpecific, 6));

            encodedParts.Add(writer.Encode());

            writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                foreach (byte[] encodedName in encodedParts)
                {
                    writer.WriteEncodedValue(encodedName);
                }
            }

            _encodedSequences.Add(writer.Encode());
        }

        public X509Extension Build(bool critical = false)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                foreach (byte[] encodedName in _encodedSequences)
                {
                    writer.WriteEncodedValue(encodedName);
                }
            }
            return new X509Extension(
                // Oids.authorityInfoAccess,
                //{iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) pe(1) authorityInfoAccess(1)}
                "1.3.6.1.5.5.7.1.1", //Authority Info Access
                writer.Encode(),
                critical);
        }
    }

    public sealed class CertificatePolicyBuilder
    {
        
        private readonly List<byte[]> _encodedSequences = [];

        /// <summary>
        /// Adding a policy Oid
        /// </summary>
        /// <param name="policyOid"></param>
        /// <param name="cps"></param>
        public void AddPolicyOid(string? policyOid, string? cps = null)
        {
            var encodedParts = new List<byte[]>();

            if (policyOid == null)
                throw new ArgumentNullException(nameof(policyOid));

            var writer = new AsnWriter(AsnEncodingRules.DER);

            writer.WriteObjectIdentifier(policyOid);
            encodedParts.Add(writer.Encode());


            if (cps != null)
            {
                writer = new AsnWriter(AsnEncodingRules.DER);
                using (writer.PushSequence())
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.3.6.1.5.5.7.2.1");
                    
                    writer.WriteCharacterString(
                        UniversalTagNumber.IA5String,
                        cps);
                }
                encodedParts.Add(writer.Encode());
            }
            
            writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                foreach (byte[] encodedName in encodedParts)
                {
                    writer.WriteEncodedValue(encodedName);
                }
            }

            _encodedSequences.Add(writer.Encode());
        }

        public X509Extension Build(bool critical = false)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                foreach (byte[] encodedName in _encodedSequences)
                {
                    writer.WriteEncodedValue(encodedName);
                }
            }
            return new X509Extension(
                // Oids.certificatePolicies
                // {joint-iso-itu-t(2) ds(5) certificateExtension(29) certificatePolicies(32)}
                "2.5.29.32", // Certificate Policies
                writer.Encode(),
                critical);
        }
    }
}
