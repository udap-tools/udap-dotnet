using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Udap.Util.Extensions;
using Xunit;

namespace Udap.Common.Tests.Util;

public class X509ExtensionTests
{
    private readonly string CertStore = "../../../../Udap.PKI.Generator/certstores";

    [Fact]
    public void ResolveUriSubjAltNameTest()
    {
#if NET9_0_OR_GREATER
        var certificate = X509CertificateLoader.LoadCertificateFromFile($"{CertStore}/localhost_fhirlabs_community1/issued/fhirLabsApiClientLocalhostCert.cer");
#else
        var certificate = new X509Certificate2($"{CertStore}/localhost_fhirlabs_community1/issued/fhirLabsApiClientLocalhostCert.cer");
#endif

        // Both should succeed.
        // The C# code cannot generated a SAN without the trailing slash on a URI without a path.
        // TODO: Need to consider issuing a PR to correct MS code base.  I think asp.net is the place.
        // But regardless I think Postels law applies here.
        Assert.Equal("https://localhost:5055/", certificate.ResolveUriSubjAltName("https://localhost:5055"));
        Assert.Equal("https://localhost:5055/", certificate.ResolveUriSubjAltName("https://localhost:5055/"));


        Assert.Equal("https://localhost:7016/fhir/r4", certificate.ResolveUriSubjAltName("https://localhost:7016/fhir/r4"));
        Assert.Equal("https://localhost:7016/fhir/r4", certificate.ResolveUriSubjAltName("https://localhost:7016/fhir/r4/"));
    }

    [Fact]
    public void KeyUsageTest()
    {
#if NET9_0_OR_GREATER
        var certificate = X509CertificateLoader.LoadCertificateFromFile($"CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var certificate = new X509Certificate2($"CertStore/anchors/SureFhirLabs_CA.cer");
#endif

        var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
        Assert.NotEmpty(extensions);

        var keyUsageStrings = extensions.Single().KeyUsages.ToKeyUsageToString().ToList();
        var crlSignIndex = keyUsageStrings.IndexOf("CrlSign");
        var keyCertSignIndex = keyUsageStrings.IndexOf("KeyCertSign");
        Assert.True(crlSignIndex >= 0, "Expected 'CrlSign' in key usage list");
        Assert.True(keyCertSignIndex >= 0, "Expected 'KeyCertSign' in key usage list");
        Assert.True(crlSignIndex < keyCertSignIndex, "Expected 'CrlSign' before 'KeyCertSign'");
    }

    [Fact]
    public void GetSubjectAltNames_NoSan_ReturnsEmpty()
    {
#if NET9_0_OR_GREATER
        var certificate = X509CertificateLoader.LoadCertificateFromFile($"{CertStore}/SurefhirCertificationLabs_Community/issued/FhirLabsAdminCertification.cer");
#else
        var certificate = new X509Certificate2($"{CertStore}/SurefhirCertificationLabs_Community/issued/FhirLabsAdminCertification.cer");
#endif

        var subjectAltNames = certificate.GetSubjectAltNames();
        Assert.Empty(subjectAltNames);
    }

    [Fact]
    public void GetSubjectAltNames_WithSans_NoFilter_ReturnsAll()
    {
#if NET9_0_OR_GREATER
        var certificate = X509CertificateLoader.LoadCertificateFromFile($"{CertStore}/localhost_fhirlabs_community1/issued/fhirLabsApiClientLocalhostCert.cer");
#else
        var certificate = new X509Certificate2($"{CertStore}/localhost_fhirlabs_community1/issued/fhirLabsApiClientLocalhostCert.cer");
#endif

        var subjectAltNames = certificate.GetSubjectAltNames();
        Assert.NotEmpty(subjectAltNames);
        Assert.All(subjectAltNames, san => Assert.False(string.IsNullOrEmpty(san.Item2)));
    }

    [Fact]
    public void Add_OidCollection_AddsAllOids()
    {
        var target = new OidCollection();
        var source = new OidCollection
        {
            new Oid("1.3.6.1.5.5.7.3.1"),
            new Oid("1.3.6.1.5.5.7.3.2")
        };

        target.Add(source);

        Assert.Equal(2, target.Count);
    }

    [Fact]
    public void Add_OidCollection_NullThrows()
    {
        var target = new OidCollection();
        Assert.Throws<ArgumentNullException>(() => target.Add((OidCollection)null!));
    }

    [Fact]
    public void Add_X509Certificate2Collection_AddsAllCerts()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var target = new X509Certificate2Collection();
        var source = new X509Certificate2Collection { cert };

        target.Add(source);

        Assert.Single(target);
        Assert.Equal(cert.Thumbprint, target[0].Thumbprint);
    }

    [Fact]
    public void Add_X509Certificate2Collection_NullThrows()
    {
        var target = new X509Certificate2Collection();
        Assert.Throws<ArgumentNullException>(() => target.Add((X509Certificate2Collection)null!));
    }

    [Fact]
    public void FindByThumbprint_ExistingCert_ReturnsCert()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var collection = new X509Certificate2Collection { cert };

        var result = collection.FindByThumbprint(cert.Thumbprint);

        Assert.NotNull(result);
        Assert.Equal(cert.Thumbprint, result!.Thumbprint);
    }

    [Fact]
    public void FindByThumbprint_NotFound_ReturnsNull()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var collection = new X509Certificate2Collection { cert };

        var result = collection.FindByThumbprint("0000000000000000000000000000000000000000");

        Assert.Null(result);
    }

    [Fact]
    public void FindByThumbprint_NullOrEmpty_ThrowsArgumentException()
    {
        var collection = new X509Certificate2Collection();
        Assert.Throws<ArgumentException>(() => collection.FindByThumbprint(null));
        Assert.Throws<ArgumentException>(() => collection.FindByThumbprint(string.Empty));
    }

    [Fact]
    public void Find_MatchingPredicate_ReturnsFirst()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var collection = new X509Certificate2Collection { cert };

        var result = collection.Find(c => c.Thumbprint == cert.Thumbprint);

        Assert.NotNull(result);
        Assert.Equal(cert.Thumbprint, result!.Thumbprint);
    }

    [Fact]
    public void Find_NoMatch_ReturnsNull()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var collection = new X509Certificate2Collection { cert };

        var result = collection.Find(c => c.Thumbprint == "nonexistent");

        Assert.Null(result);
    }

    [Fact]
    public void IndexOf_MatchingPredicate_ReturnsIndex()
    {
#if NET9_0_OR_GREATER
        var cert1 = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var cert2 = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var cert1 = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var cert2 = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif
        var collection = new X509Certificate2Collection { cert1, cert2 };

        var index = collection.IndexOf(c => c.Thumbprint == cert2.Thumbprint);

        Assert.Equal(1, index);
    }

    [Fact]
    public void IndexOf_NoMatch_ReturnsNegativeOne()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var collection = new X509Certificate2Collection { cert };

        var index = collection.IndexOf(c => c.Thumbprint == "nonexistent");

        Assert.Equal(-1, index);
    }

    [Fact]
    public void IndexOf_EmptyCollection_ReturnsNegativeOne()
    {
        var collection = new X509Certificate2Collection();
        var index = collection.IndexOf(c => c.Subject.Contains("Test"));
        Assert.Equal(-1, index);
    }

    [Fact]
    public void ToX509Collection_EmptyArray_ReturnsNull()
    {
        var result = Array.Empty<X509Certificate2>().ToX509Collection();
        Assert.Null(result);
    }

    [Fact]
    public void ToX509Collection_WithCerts_ReturnsCollection()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var result = new[] { cert }.ToX509Collection();

        Assert.NotNull(result);
        Assert.Single(result!);
        Assert.Equal(cert.Thumbprint, result![0].Thumbprint);
    }

    [Fact]
    public void ToPemFormat_NullCert_ReturnsEmpty()
    {
        X509Certificate2? cert = null;
        var result = cert.ToPemFormat();
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void ToPemFormat_ValidCert_ReturnsPemString()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var result = cert.ToPemFormat();

        Assert.Contains("-----BEGIN CERTIFICATE-----", result);
        Assert.Contains("-----END CERTIFICATE-----", result);
    }

    [Fact]
    public void ToRootCertArray_IdentifiesRootsOnly()
    {
#if NET9_0_OR_GREATER
        var rootCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var rootCert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        var certs = new List<X509Certificate2> { rootCert, intermediateCert };
        var roots = certs.ToRootCertArray();

        Assert.Single(roots);
        Assert.Equal(rootCert.Thumbprint, roots[0].Thumbprint);
    }

    [Fact]
    public void ToRootCertArray_EmptyList_ReturnsEmpty()
    {
        var certs = new List<X509Certificate2>();
        var roots = certs.ToRootCertArray();
        Assert.Empty(roots);
    }

    [Fact]
    public void FromTag_ValidTagNo_ReturnsCorrectEnum()
    {
        var result = X509Extensions.FromTag<X509Extensions.GeneralNameType>(6);
        Assert.Equal(X509Extensions.GeneralNameType.URI, result);
    }

    [Fact]
    public void FromTag_DnsTagNo_ReturnsDns()
    {
        var result = X509Extensions.FromTag<X509Extensions.GeneralNameType>(2);
        Assert.Equal(X509Extensions.GeneralNameType.DNS, result);
    }

    [Fact]
    public void GetExtensionValue_BasicConstraints_ReturnsValue()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var result = cert.GetExtensionValue("2.5.29.19");
        Assert.NotNull(result);
    }

    [Fact]
    public void GetExtensionValue_NonExistentOid_ReturnsNull()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        var result = cert.GetExtensionValue("1.2.3.4.5.6.7.8.9");
        Assert.Null(result);
    }

    [Fact]
    public void Summarize_ChainStatuses_FiltersMatchingFlags()
    {
        var statuses = new[]
        {
            new X509ChainStatus
            {
                Status = X509ChainStatusFlags.UntrustedRoot,
                StatusInformation = "untrusted root"
            },
            new X509ChainStatus
            {
                Status = X509ChainStatusFlags.NotTimeValid,
                StatusInformation = "expired"
            },
            new X509ChainStatus
            {
                Status = X509ChainStatusFlags.RevocationStatusUnknown,
                StatusInformation = "revocation unknown"
            }
        };

        var result = statuses.Summarize(
            X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.NotTimeValid);

        Assert.Contains("untrusted root", result);
        Assert.Contains("expired", result);
        Assert.DoesNotContain("revocation unknown", result);
    }

    [Fact]
    public void Summarize_ChainStatuses_EmptyArray_ReturnsEmpty()
    {
        var statuses = Array.Empty<X509ChainStatus>();
        var result = statuses.Summarize(X509ChainStatusFlags.UntrustedRoot);
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void Summarize_ChainStatuses_NoMatchingFlags_ReturnsEmpty()
    {
        var statuses = new[]
        {
            new X509ChainStatus
            {
                Status = X509ChainStatusFlags.RevocationStatusUnknown,
                StatusInformation = "revocation unknown"
            }
        };

        var result = statuses.Summarize(X509ChainStatusFlags.UntrustedRoot);
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void Summarize_ChainElementCollection_NoProblems_ReturnsNewlineOnly()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(cert);
        chain.Build(cert);

        var result = chain.ChainElements.Summarize();

        Assert.NotNull(result);
        Assert.DoesNotContain("SubAltName", result);
    }

    [Fact]
    public void Summarize_ChainElementCollection_WithProblems_IncludesStatusInfo()
    {
#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            "CertStore/issued/fhirlabs.net.expired.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);
#else
        var cert = new X509Certificate2(
            "CertStore/issued/fhirlabs.net.expired.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);
#endif

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.Build(cert);

        var result = chain.ChainElements.Summarize();

        Assert.Contains("SubAltName", result);
    }

    [Fact]
    public void ToKeyUsageToString_DigitalSignature_ReturnsSingleFlag()
    {
        var flags = X509KeyUsageFlags.DigitalSignature;
        var result = flags.ToKeyUsageToString().ToList();

        Assert.Single(result);
        Assert.Equal("DigitalSignature", result[0]);
    }

    [Fact]
    public void ToKeyUsageToString_AllFlags_ReturnsAllNineFlags()
    {
        var flags = X509KeyUsageFlags.KeyAgreement
                    | X509KeyUsageFlags.CrlSign
                    | X509KeyUsageFlags.DataEncipherment
                    | X509KeyUsageFlags.DecipherOnly
                    | X509KeyUsageFlags.DigitalSignature
                    | X509KeyUsageFlags.EncipherOnly
                    | X509KeyUsageFlags.KeyCertSign
                    | X509KeyUsageFlags.KeyEncipherment
                    | X509KeyUsageFlags.NonRepudiation;

        var result = flags.ToKeyUsageToString().ToList();

        Assert.Equal(9, result.Count);
        Assert.Contains("KeyAgreement", result);
        Assert.Contains("CrlSign", result);
        Assert.Contains("DataEncipherment", result);
        Assert.Contains("DecipherOnly", result);
        Assert.Contains("DigitalSignature", result);
        Assert.Contains("EncipherOnly", result);
        Assert.Contains("KeyCertSign", result);
        Assert.Contains("KeyEncipherment", result);
        Assert.Contains("NonRepudiation", result);
    }

    [Fact]
    public void ToKeyUsageToString_None_ReturnsEmpty()
    {
        var flags = X509KeyUsageFlags.None;
        var result = flags.ToKeyUsageToString().ToList();
        Assert.Empty(result);
    }

    [Fact]
    public void ToKeyUsageToString_EndEntityFlags_ReturnsCorrectSubset()
    {
        var flags = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment;
        var result = flags.ToKeyUsageToString().ToList();

        Assert.Equal(2, result.Count);
        Assert.Contains("DigitalSignature", result);
        Assert.Contains("KeyEncipherment", result);
    }

    [Fact]
    public void ToKeyUsageToString_JoinedForDisplay_MatchesUdapEdPattern()
    {
        var flags = X509KeyUsageFlags.DigitalSignature
                    | X509KeyUsageFlags.KeyEncipherment
                    | X509KeyUsageFlags.NonRepudiation;

        var display = string.Join("; ", flags.ToKeyUsageToString());

        Assert.Contains("DigitalSignature", display);
        Assert.Contains("KeyEncipherment", display);
        Assert.Contains("NonRepudiation", display);
    }
}
