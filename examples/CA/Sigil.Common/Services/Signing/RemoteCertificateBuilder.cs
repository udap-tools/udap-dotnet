#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Sigil.Common.Services.Signing;

/// <summary>
/// Builds X.509 certificates using BouncyCastle to compute TBS (to-be-signed) bytes,
/// then signs asynchronously via ISigningProvider, and assembles the final DER certificate.
/// This avoids the sync-over-async deadlock that would occur with BouncyCastle's
/// synchronous ISignatureFactory in Blazor Server's sync context.
/// </summary>
public static class RemoteCertificateBuilder
{
    /// <summary>
    /// Creates a self-signed root CA certificate using remote signing.
    /// </summary>
    public static async Task<X509Certificate2> CreateSelfSignedAsync(
        ISigningProvider provider,
        SigningKeyReference keyRef,
        string subjectDn,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        X509Extension[] extensions,
        HashAlgorithmName hashAlgorithm,
        CancellationToken ct = default)
    {
        var publicKey = await provider.GetPublicKeyAsync(keyRef, ct);
        var bcPublicKey = ConvertToBouncyCastlePublicKey(publicKey);

        var tbsGen = new V3TbsCertificateGenerator();
        var subject = new X509Name(subjectDn);
        var serialNumber = GenerateSerialNumber();
        var sigAlgId = GetSignatureAlgorithmIdentifier(keyRef.KeyAlgorithm, hashAlgorithm);

        tbsGen.SetSerialNumber(new DerInteger(serialNumber));
        tbsGen.SetIssuer(subject);
        tbsGen.SetSubject(subject);
        tbsGen.SetStartDate(new Org.BouncyCastle.Asn1.X509.Time(notBefore.UtcDateTime));
        tbsGen.SetEndDate(new Org.BouncyCastle.Asn1.X509.Time(notAfter.UtcDateTime));
        tbsGen.SetSubjectPublicKeyInfo(
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcPublicKey));
        tbsGen.SetSignature(sigAlgId);

        // Add extensions
        var extGen = new X509ExtensionsGenerator();
        foreach (var ext in extensions)
        {
            var oid = new DerObjectIdentifier(ext.Oid!.Value!);
            extGen.AddExtension(oid, ext.Critical,
                Asn1Object.FromByteArray(ext.RawData));
        }
        tbsGen.SetExtensions(extGen.Generate());

        // Generate TBS bytes
        var tbsCert = tbsGen.GenerateTbsCertificate();
        var tbsBytes = tbsCert.GetDerEncoded();

        // Sign asynchronously via the provider (no sync-over-async deadlock)
        var signature = await provider.SignDataAsync(tbsBytes, hashAlgorithm, keyRef, ct);

        // Assemble the final X.509 certificate: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        var certDer = AssembleCertificateDer(tbsCert, sigAlgId, signature);

        return X509CertificateLoader.LoadCertificate(certDer);
    }

    /// <summary>
    /// Creates a CA-signed certificate (intermediate CA or end-entity) using remote signing.
    /// </summary>
    public static async Task<X509Certificate2> CreateSignedAsync(
        ISigningProvider provider,
        SigningKeyReference issuerKeyRef,
        X509Certificate2 issuerCert,
        AsymmetricAlgorithm subjectPublicKey,
        string subjectDn,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        X509Extension[] extensions,
        HashAlgorithmName hashAlgorithm,
        CancellationToken ct = default)
    {
        var bcSubjectPublicKey = ConvertToBouncyCastlePublicKey(subjectPublicKey);

        var tbsGen = new V3TbsCertificateGenerator();
        var issuerDn = new X509Name(issuerCert.Subject);
        var subject = new X509Name(subjectDn);
        var serialNumber = GenerateSerialNumber();
        var sigAlgId = GetSignatureAlgorithmIdentifier(issuerKeyRef.KeyAlgorithm, hashAlgorithm);

        tbsGen.SetSerialNumber(new DerInteger(serialNumber));
        tbsGen.SetIssuer(issuerDn);
        tbsGen.SetSubject(subject);
        tbsGen.SetStartDate(new Org.BouncyCastle.Asn1.X509.Time(notBefore.UtcDateTime));
        tbsGen.SetEndDate(new Org.BouncyCastle.Asn1.X509.Time(notAfter.UtcDateTime));
        tbsGen.SetSubjectPublicKeyInfo(
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcSubjectPublicKey));
        tbsGen.SetSignature(sigAlgId);

        // Add extensions
        var extGen = new X509ExtensionsGenerator();
        foreach (var ext in extensions)
        {
            var oid = new DerObjectIdentifier(ext.Oid!.Value!);
            extGen.AddExtension(oid, ext.Critical,
                Asn1Object.FromByteArray(ext.RawData));
        }
        tbsGen.SetExtensions(extGen.Generate());

        // Generate TBS bytes
        var tbsCert = tbsGen.GenerateTbsCertificate();
        var tbsBytes = tbsCert.GetDerEncoded();

        // Sign asynchronously via the provider
        var signature = await provider.SignDataAsync(tbsBytes, hashAlgorithm, issuerKeyRef, ct);

        // Assemble the final certificate
        var certDer = AssembleCertificateDer(tbsCert, sigAlgId, signature);

        return X509CertificateLoader.LoadCertificate(certDer);
    }

    /// <summary>
    /// Assembles a DER-encoded X.509 certificate from TBS, algorithm, and signature.
    /// Structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
    /// </summary>
    private static byte[] AssembleCertificateDer(
        TbsCertificateStructure tbsCert,
        AlgorithmIdentifier sigAlgId,
        byte[] signatureBytes)
    {
        var certSeq = new DerSequence(
            tbsCert,
            sigAlgId,
            new DerBitString(signatureBytes));

        return certSeq.GetDerEncoded();
    }

    internal static AlgorithmIdentifier GetSignatureAlgorithmIdentifier(
        string keyAlgorithm, HashAlgorithmName hashAlgorithm)
    {
        if (keyAlgorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase))
        {
            var oid = hashAlgorithm.Name switch
            {
                "SHA384" => Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha384WithRsaEncryption,
                "SHA512" => Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha512WithRsaEncryption,
                _ => Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha256WithRsaEncryption
            };
            return new AlgorithmIdentifier(oid, DerNull.Instance);
        }
        else // ECDSA
        {
            var oid = hashAlgorithm.Name switch
            {
                "SHA384" => Org.BouncyCastle.Asn1.X9.X9ObjectIdentifiers.ECDsaWithSha384,
                "SHA512" => Org.BouncyCastle.Asn1.X9.X9ObjectIdentifiers.ECDsaWithSha512,
                _ => Org.BouncyCastle.Asn1.X9.X9ObjectIdentifiers.ECDsaWithSha256
            };
            return new AlgorithmIdentifier(oid);
        }
    }

    private static AsymmetricKeyParameter ConvertToBouncyCastlePublicKey(AsymmetricAlgorithm key)
    {
        byte[] spki;
        if (key is RSA rsa)
        {
            spki = rsa.ExportSubjectPublicKeyInfo();
        }
        else if (key is ECDsa ecdsa)
        {
            spki = ecdsa.ExportSubjectPublicKeyInfo();
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type: {key.GetType().Name}");
        }

        return Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(spki);
    }

    private static Org.BouncyCastle.Math.BigInteger GenerateSerialNumber()
    {
        var serialBytes = RandomNumberGenerator.GetBytes(16);
        serialBytes[0] &= 0x7F; // Ensure positive
        return new Org.BouncyCastle.Math.BigInteger(1, serialBytes);
    }
}
