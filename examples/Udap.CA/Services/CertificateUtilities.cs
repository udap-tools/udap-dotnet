#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Udap.CA.Services;

public class CertificateUtilities : IDisposable
{
    private X509Certificate2? _certificate;
    private readonly RSA _rsaKey;

    public CertificateUtilities(RSA? rsa = null)
    {
        if (rsa != null)
        {
            _rsaKey = rsa;
        }

        _rsaKey = RSA.Create(4096);
    }

    public X509Certificate2 GenerateRootCA(string subject)
    {
        var parentReq = new CertificateRequest(
            subject,
            _rsaKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        parentReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        parentReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign,
                true));

        parentReq.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                    new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                    new Oid("1.3.6.1.5.5.7.3.8") // Time Stamping
                },
                true));

        parentReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

        _certificate = parentReq.CreateSelfSigned(
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddYears(10));
        
        return _certificate;
    }
    
    public X509Certificate2 GenerateIntermediate(
        string subject,
        Uri subjectAltName,
        Uri certificateRevocation,
        Uri certificateAuthIssuerUri,
        X509Certificate2 issuerCertificate)
    {
        var intermediateRequest = new CertificateRequest(
                        subject,
                        _rsaKey,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

        // Referred to as intermediate Cert or Anchor
        intermediateRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        intermediateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign,
                true));

        intermediateRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));

        AddAuthorityKeyIdentifier(issuerCertificate, intermediateRequest);
        intermediateRequest.CertificateExtensions.Add(MakeCdp(certificateRevocation));

        var subAltNameBuilder = new SubjectAlternativeNameBuilder();
        subAltNameBuilder.AddUri(subjectAltName);
        var x509Extension = subAltNameBuilder.Build();
        intermediateRequest.CertificateExtensions.Add(x509Extension);

        var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
        authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(certificateAuthIssuerUri);
        var aiaExtension = authorityInfoAccessBuilder.Build();
        intermediateRequest.CertificateExtensions.Add(aiaExtension);
        
        _certificate = intermediateRequest.Create(
                   issuerCertificate,
                   DateTimeOffset.UtcNow,
                   DateTimeOffset.UtcNow.AddYears(5),
                   new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));

        return _certificate.CopyWithPrivateKey(_rsaKey);
    }

    // TODO: Need to be able to generate multiple subjectAltNames, maybe. 
    public X509Certificate2 GenerateEndCert(string subject,
        Uri subjectAltName,
        Uri certificateRevocation,
        Uri certificateAuthIssuerUri,
        X509Certificate2 issuerCertificate)
    {
        var sureFhirLabsClientReq = new CertificateRequest(
                            subject,
                            _rsaKey,
                            HashAlgorithmName.SHA256,
                            RSASignaturePadding.Pkcs1);

        sureFhirLabsClientReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        sureFhirLabsClientReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                false));

        sureFhirLabsClientReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(sureFhirLabsClientReq.PublicKey, false));

        AddAuthorityKeyIdentifier(issuerCertificate, sureFhirLabsClientReq);

        sureFhirLabsClientReq.CertificateExtensions.Add(MakeCdp(certificateRevocation));

        var subAltNameBuilder = new SubjectAlternativeNameBuilder();

        //
        // Just here for what if scenario for now.
        //
        //subAltNameBuilder.AddUri(new Uri("http://localhost")); //Same as iss claim
        
        subAltNameBuilder.AddUri(subjectAltName); //Same as iss claim
        
        var x509Extension = subAltNameBuilder.Build();
        sureFhirLabsClientReq.CertificateExtensions.Add(x509Extension);

        var authorityInfoAccessBuilder = new AuthorityInformationAccessBuilder();
        authorityInfoAccessBuilder.AdCertificateAuthorityIssuerUri(certificateAuthIssuerUri);
        var aiaExtension = authorityInfoAccessBuilder.Build();
        sureFhirLabsClientReq.CertificateExtensions.Add(aiaExtension);

        var clientCert = sureFhirLabsClientReq.Create(
                   issuerCertificate,
                   DateTimeOffset.UtcNow,
                   DateTimeOffset.UtcNow.AddYears(2),
                   new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));

        return clientCert.CopyWithPrivateKey(_rsaKey);
    }

    private static X509Extension MakeCdp(Uri uri)
    {
        //
        // urls less than 119 char solution.
        // From Bartonjs of course.
        //
        // https://stackoverflow.com/questions/60742814/add-crl-distribution-points-cdp-extension-to-x509certificate2-certificate
        //
        // From Crypt32:  .NET doesn't support CDP extension. You have to use 3rd party libraries for that. BC is ok if it works for you.
        // Otherwise write you own. :)
        //

        byte[] encodedUrl = Encoding.ASCII.GetBytes(uri.AbsoluteUri);

        if (encodedUrl.Length > 119)
        {
            throw new NotSupportedException();
        }

        byte[] payload = new byte[encodedUrl.Length + 10];
        int offset = 0;
        payload[offset++] = 0x30;
        payload[offset++] = (byte)(encodedUrl.Length + 8);
        payload[offset++] = 0x30;
        payload[offset++] = (byte)(encodedUrl.Length + 6);
        payload[offset++] = 0xA0;
        payload[offset++] = (byte)(encodedUrl.Length + 4);
        payload[offset++] = 0xA0;
        payload[offset++] = (byte)(encodedUrl.Length + 2);
        payload[offset++] = 0x86;
        payload[offset++] = (byte)(encodedUrl.Length);
        Buffer.BlockCopy(encodedUrl, 0, payload, offset, encodedUrl.Length);

        return new X509Extension("2.5.29.31", payload, critical: false);
    }

    private static void AddAuthorityKeyIdentifier(X509Certificate2 caCert, CertificateRequest anchorReq)
    {
        //
        // Found way to generate intermediate below
        //
        // https://github.com/rwatjen/AzureIoTDPSCertificates/blob/711429e1b6dee7857452233a73f15c22c2519a12/src/DPSCertificateTool/CertificateUtil.cs#L69
        // https://blog.rassie.dk/2018/04/creating-an-x-509-certificate-chain-in-c/
        //


        var issuerSubjectKey = caCert.Extensions["2.5.29.14"]?.RawData;
        if (issuerSubjectKey != null)
        {
            var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
            var authorityKeyIdentifier = new byte[segment.Count + 4];
            // these bytes define the "KeyID" part of the AuthorityKeyIdentifier
            authorityKeyIdentifier[0] = 0x30;
            authorityKeyIdentifier[1] = 0x16;
            authorityKeyIdentifier[2] = 0x80;
            authorityKeyIdentifier[3] = 0x14;
            segment.CopyTo(authorityKeyIdentifier, 4);
            anchorReq.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
        }
    }

    private void Dispose(bool disposing)
    {
        if (disposing)
        {
            _certificate?.Dispose();
            _rsaKey.Dispose();
        }
    }

    /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Allows an object to try to free resources and perform other cleanup operations before it is reclaimed by garbage collection.</summary>
    ~CertificateUtilities()
    {
        Dispose(false);
    }
}
