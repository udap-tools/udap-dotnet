using System.Formats.Asn1;
using FluentAssertions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Udap.CA.Services;
using Udap.Util.Extensions;


namespace Udap.CA.Tests;

public class UnitTest1
{
    [Fact]
    public void GenerateRootCertTestWithDispose()
    {
        var subject = "CN=SureFhir-TestCA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US";

        using var certificateUtilities = new CertificateUtilities();
        var rootCert = certificateUtilities.GenerateRootCA(subject);

        rootCert.Subject.Should().Be(subject);
        rootCert.HasPrivateKey.Should().BeTrue();
        rootCert.Issuer.Should().Be(subject);

        certificateUtilities.Dispose();

        //
        // Just exercising dispose test behavior
        //
        Action action = () => rootCert.Subject.ToString();
        action.Should().Throw<CryptographicException>().Subject
            .First().Message.Should()
            .BeEquivalentTo("m_safeCertContext is an invalid handle.");
    }

    [Fact]
    public X509Certificate2 GenerateRootCertTest()
    {
        var subject = "CN=SureFhir-TestCA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US";

        var certificateUtilities = new CertificateUtilities();
        var rootCert = certificateUtilities.GenerateRootCA(subject);

        rootCert.Subject.Should().Be(subject);
        rootCert.HasPrivateKey.Should().BeTrue();
        rootCert.Issuer.Should().Be(subject);

        return rootCert;
    }

    [Fact]
    public X509Certificate2 GenerateIntermediateCertTest()
    {
        var rootCertificate = GenerateRootCertTest();
        
        var subject = "CN=SureFhir-TestAnchor, OU=Anchor, O=Fhir Coding, L=Portland, S=Oregon, C=US";
        var subjectAltName = new Uri("http://fhirwalker.com");
        var crl = new Uri("http://crl.fhircerts.net/crl/SureFhir-TestAnchor.crl");
        var certificateAuthIssuerUri = new Uri("http://crl.fhircerts.net/certs/intermediates/SureFhir-TestAnchor.cer");
        
        var certificateUtilities = new CertificateUtilities();

        var intermediateCertificate = certificateUtilities.GenerateIntermediate(
            subject,
            subjectAltName,
            crl,
            certificateAuthIssuerUri,
            rootCertificate);

        intermediateCertificate.Subject.Should().Be(subject);
        intermediateCertificate.HasPrivateKey.Should().BeTrue();
        intermediateCertificate.Issuer.Should().Be(rootCertificate.Subject);

        return intermediateCertificate;
    }

    [Fact]
    public void GenerateIssuedCertTest()
    {
        var intermediateCertificate = GenerateIntermediateCertTest();

        var subject = "CN=test.fhirlabs.net, OU=Do not use for PHI, O=Fhir Coding, L=Portland, S=Oregon, C=US";
        var subjectAltName = new Uri("https://test.fhirlabs.net/fhir/r4");
        var crl = new Uri("http://crl.fhircerts.net/crl/surefhirlabs.crl");
        var certificateAuthIssuerUri = new Uri("http://crl.fhircerts.net/certs/intermediates/SureFhirLabs_Intermediate.cer");

        var certificateUtilities = new CertificateUtilities();

        var issuedCertificate = certificateUtilities.GenerateEndCert(
            subject,
            subjectAltName,
            crl,
            certificateAuthIssuerUri,
            intermediateCertificate);


        issuedCertificate.Subject.Should().Be(subject);
        //
        // It might be cool to try using the Microsoft AsnReader instead of BouncyCastle.
        // Good resources here:
        // https://stackoverflow.com/questions/70217305/how-to-use-system-formats-asn1-asnreader
        // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Formats.Asn1/tests/Reader/ReadSequence.cs
        // https://github.com/dotnet/designs/blob/ec974c0b7d87d984f498651af2a3e157ba579f01/accepted/2020/asnreader/asnreader.md
        //
        issuedCertificate.GetExtensionValue("1.3.6.1.5.5.7.1.1");

        issuedCertificate.HasPrivateKey.Should().BeTrue();
        issuedCertificate.Issuer.Should().Be(intermediateCertificate.Subject);

        var aiaExtensions =
            issuedCertificate.Extensions["1.3.6.1.5.5.7.1.1"] as X509AuthorityInformationAccessExtension;
        aiaExtensions.Should().NotBeNull();
        aiaExtensions!.EnumerateCAIssuersUris().Single().Should().Be(certificateAuthIssuerUri.AbsoluteUri);

        //
        // No good because it just gets the first one
        //
        var joe = issuedCertificate.GetNameInfo(X509NameType.UrlName, false);


        var subjectAltNameExtension =
            issuedCertificate.Extensions["2.5.29.17"]  as X509SubjectAlternativeNameExtension;

        //
        // This is but wont work for UDAP because the string sent to MatchesHostname must be a domain name
        // test.fhirlabs.net would work but test.fhirlabs.net/fhir/r4 would not
        //
        // Actually MatchesHostname is not build for checking a Uri.  Internally is gets a X509SubjectAlternativeNameExtension
        // like on the previous code line and has access to two enumerates methods; EnumerateDnsNames() and EnumerateIPAddresses().
        // There is no EnumerateUris().  So we should write one. TODO
        //
        // So the next line would work great as an SSL validation but not for UDAP
        // issuedCertificate.MatchesHostname("test.fhirlabs.net").Should().BeTrue();
        // 
        // Below is some code that uses the AsnReader to find the URI


        // char[] clientPem = PemEncoding.Write("CERTIFICATE", issuedCertificate.RawData);
        // File.WriteAllBytes($"__Test__.cer", clientPem.Select(c => (byte)c).ToArray());
        


        //TODO: this code needs to be put into a library so we can used it to assert subAltName the same as iss and url etc...
        ReadOnlyMemory<byte> encoded = subjectAltNameExtension.RawData;
        AsnReader reader = new AsnReader(subjectAltNameExtension.RawData, AsnEncodingRules.DER);
        reader.HasData.Should().BeTrue();
        AsnReader sanExtensionValue = reader.ReadSequence();
        reader.HasData.Should().BeFalse();
        Asn1Tag uriName = new Asn1Tag(TagClass.ContextSpecific, 6);

        //
        // extra subAltName for what if scenario for now.  Future work.
        //
        // sanExtensionValue.ReadCharacterString(UniversalTagNumber.IA5String, uriName).Should().Be("http://localhost/");
        
        sanExtensionValue.ReadCharacterString(UniversalTagNumber.IA5String, uriName).Should().Be(subjectAltName.AbsoluteUri);

    }
    
}