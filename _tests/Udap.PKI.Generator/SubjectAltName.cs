#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Org.BouncyCastle.Asn1.X509;

namespace Udap.PKI.Generator;

/// <summary>
/// Builds a Subject Alternative Name extension whose uniformResourceIdentifier entries are
/// written exactly as given.
/// <para>
/// <see cref="System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder.AddUri"/>
/// encodes <see cref="Uri.AbsoluteUri"/>, and .NET canonicalizes a URI with an empty path to one
/// ending in "/". A SAN of <c>https://idp.example.com</c> therefore came out as
/// <c>https://idp.example.com/</c>. The UDAP Security IG requires the JWT <c>iss</c> to match the
/// SAN as an exact string, trailing slash included, so SAN URIs are emitted verbatim instead.
/// </para>
/// </summary>
internal static class SubjectAltName
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    /// <summary>
    /// Creates a non-critical SAN extension containing one uniformResourceIdentifier per entry.
    /// A trailing slash is rejected so that a FHIR base URL or IdP URL is never issued in a form
    /// the JWT producer would then have to reproduce character for character.
    /// </summary>
    public static System.Security.Cryptography.X509Certificates.X509Extension FromUris(IEnumerable<string> uris)
    {
        var names = uris.Select(uri =>
        {
            if (string.IsNullOrWhiteSpace(uri))
            {
                throw new ArgumentException("SAN URI cannot be empty.", nameof(uris));
            }

            if (uri.EndsWith('/'))
            {
                throw new ArgumentException($"SAN URI must not end with a trailing slash: {uri}", nameof(uris));
            }

            return new GeneralName(GeneralName.UniformResourceIdentifier, uri);
        }).ToArray();

        return new System.Security.Cryptography.X509Certificates.X509Extension(
            SubjectAlternativeNameOid,
            new GeneralNames(names).GetDerEncoded(),
            critical: false);
    }
}
