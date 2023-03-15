#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Udap.CA.Services
{
    public sealed class AuthorityInformationAccessBuilder
    {
        private List<byte[]> _encodedUrls = new List<byte[]>();
        private readonly List<byte[]> _encodedSequences = new List<byte[]>();
        /// <summary>
        /// Adding ObjectIdentifier (OID) 1.3.6.1.5.5.7.48.2
        /// </summary>
        /// <param name="uri"></param>
        public void AdCertificateAuthorityIssuerUri(Uri uri)
        {
            if (uri == null) 
                throw new ArgumentNullException(nameof(uri));
            
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            
            writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2");
            _encodedUrls.Add(writer.Encode());

            writer = new AsnWriter(AsnEncodingRules.DER);

            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, 
                uri.AbsoluteUri, 
                new Asn1Tag(TagClass.ContextSpecific, 6));

            _encodedUrls.Add(writer.Encode());

            writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                foreach (byte[] encodedName in _encodedUrls)
                {
                    writer.WriteEncodedValue(encodedName);
                }
            }

            _encodedSequences.Add(writer.Encode());
        }

        public X509Extension Build(bool critical = false)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                foreach (byte[] encodedName in _encodedSequences)
                {
                    writer.WriteEncodedValue(encodedName);
                }
            }
            return new X509Extension(
                // Oids AuthorityInfoAccessSyntax,
                "1.3.6.1.5.5.7.1.1",
                writer.Encode(),
                critical);
        }
    }
}
