#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Models;
using Xunit;
// ReSharper disable SuspiciousTypeConversion.Global

namespace Udap.Common.Tests.Models;

public class ModelTests
{

    [Fact]
    public void SimpleAnchorTest()
    {
#if NET9_0_OR_GREATER
        var certificate = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var certificate = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif

        var anchor = new Anchor(certificate, "community1");

        Assert.True(anchor.Equals(anchor));
        Assert.True(anchor.Equals(anchor as object));

        var secondAnchor = new Anchor(certificate, "community2");
        Assert.False(anchor.Equals(secondAnchor));
        Assert.False(anchor.Equals(secondAnchor as object));

        Assert.False(anchor.Equals(new object()));
        Assert.False(anchor.Equals(null));

        Assert.Equal(certificate.NotAfter, anchor!.EndDate);
        Assert.Equal(certificate.NotBefore, anchor.BeginDate);
        Assert.False(anchor.Enabled);
        Assert.Equal(0, anchor.Id);

        Assert.Contains("Name CN=SureFhir-CA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US | Community community1", anchor.ToString());

        Assert.NotEqual(secondAnchor.GetHashCode(), anchor.GetHashCode());
    }

    [Fact]
    public void IntermediateTest()
    {
#if NET9_0_OR_GREATER
        var intermediateCertificate = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var intermediateCertificate = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        var intermediate = new Intermediate(intermediateCertificate);

        Assert.True(intermediate.Equals(intermediate));
        Assert.True(intermediate.Equals(intermediate as object));

#if NET9_0_OR_GREATER
        var secondAnchor = new Anchor(X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer"));
#else
        var secondAnchor = new Anchor(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer"));
#endif
        Assert.False(intermediate.Equals(secondAnchor));

        Assert.False(intermediate.Equals(new object()));
        Assert.False(intermediate.Equals(null));
        Assert.False(intermediate!.Equals(null as Anchor));

        Assert.Equal(intermediateCertificate.NotAfter, intermediate.EndDate);
        Assert.Equal(intermediateCertificate.NotBefore, intermediate.BeginDate);
        Assert.False(intermediate.Enabled);
        Assert.Equal(0, intermediate.Id);

        Assert.Contains("| Name CN=SureFhir-Intermediate, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US", intermediate.ToString());

#if NET9_0_OR_GREATER
        var anchorCertificate = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var anchorCertificate = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif
        intermediate.Anchor = new Anchor(anchorCertificate);
        Assert.Equal(0, intermediate.AnchorId);
        Assert.False(string.IsNullOrWhiteSpace(intermediate.Anchor.Thumbprint));

#if NET9_0_OR_GREATER
        var secondIntermediate = new Intermediate(X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer"));
#else
        var secondIntermediate = new Intermediate(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer"));
#endif
        Assert.NotEqual(secondIntermediate.GetHashCode(), intermediate.GetHashCode());
    }

    [Fact]
    public void IssuedCertificateTest()
    {
#if NET9_0_OR_GREATER
        var issuedCertificate = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var issuedCertificate = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var issued = new IssuedCertificate(issuedCertificate);

        Assert.True(issued.Equals(issued));
        Assert.True(issued.Equals(issued as object));

        var secondIssued = new IssuedCertificate(issuedCertificate, "community2");
        Assert.False(issued.Equals(secondIssued));
        Assert.False(issued.Equals(secondIssued as object));

        Assert.False(issued.Equals(new object()));
        Assert.False(issued.Equals(null));

        Assert.NotEqual(secondIssued.GetHashCode(), issued!.GetHashCode());
    }

    [Fact]
    public void IssuedCertificate_DefaultConstructor()
    {
        var issued = new IssuedCertificate();
        Assert.NotNull(issued);
    }

    [Fact]
    public void Anchor_DefaultConstructor_CanSetProperties()
    {
        var anchor = new Anchor();

        anchor.Id = 1;
        anchor.Enabled = true;
        anchor.Name = "Test Anchor";
        anchor.Community = "udap://test";
        anchor.CommunityId = 5;
        anchor.Certificate = "PEM-DATA";
        anchor.Thumbprint = "ABC123";
        anchor.BeginDate = new DateTime(2024, 1, 1);
        anchor.EndDate = new DateTime(2025, 1, 1);
        anchor.Intermediates = new List<Intermediate>();

        Assert.Equal(1, anchor.Id);
        Assert.True(anchor.Enabled);
        Assert.Equal("Test Anchor", anchor.Name);
        Assert.Equal("udap://test", anchor.Community);
        Assert.Equal(5, anchor.CommunityId);
        Assert.Equal("PEM-DATA", anchor.Certificate);
        Assert.Equal("ABC123", anchor.Thumbprint);
        Assert.Equal(new DateTime(2024, 1, 1), anchor.BeginDate);
        Assert.Equal(new DateTime(2025, 1, 1), anchor.EndDate);
        Assert.Empty(anchor.Intermediates);
    }

    [Fact]
    public void Intermediate_DefaultConstructor_CanSetProperties()
    {
        var intermediate = new Intermediate();

        intermediate.Id = 2;
        intermediate.AnchorId = 1;
        intermediate.Enabled = true;
        intermediate.Name = "Test Intermediate";
        intermediate.Certificate = "PEM-DATA";
        intermediate.Thumbprint = "DEF456";
        intermediate.BeginDate = new DateTime(2024, 1, 1);
        intermediate.EndDate = new DateTime(2025, 1, 1);
        intermediate.Anchor = new Anchor();

        Assert.Equal(2, intermediate.Id);
        Assert.Equal(1, intermediate.AnchorId);
        Assert.True(intermediate.Enabled);
        Assert.Equal("Test Intermediate", intermediate.Name);
        Assert.Equal("PEM-DATA", intermediate.Certificate);
        Assert.Equal("DEF456", intermediate.Thumbprint);
        Assert.Equal(new DateTime(2024, 1, 1), intermediate.BeginDate);
        Assert.Equal(new DateTime(2025, 1, 1), intermediate.EndDate);
        Assert.NotNull(intermediate.Anchor);
    }

    [Fact]
    public void SimpleCommunityTest()
    {
        var community = new Community
        {
            Default = true,
            Anchors = new List<Anchor>()
        };
#if NET9_0_OR_GREATER
        community.Anchors.Add(new Anchor(X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer")));
        community.Anchors.Add(new Anchor(X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer")));
#else
        community.Anchors.Add(new Anchor(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer")));
        community.Anchors.Add(new Anchor(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer")));
#endif
        community.Certifications = new List<Certification>();
        community.Certifications.Add(new Certification());
        community.Certifications.Add(new Certification());

        Assert.Equal(0, community.Id);
        Assert.Equal(2, community.Anchors.Count);
        Assert.Equal(2, community.Certifications.Count);
        Assert.True(community.Default);
    }

    [Fact]
    public void SimpleCertificationTest()
    {
        var certification = new Certification();
        Assert.Equal(0, certification.Id);
        certification.Name = "Cert1";
        Assert.Equal("Cert1", certification.Name);
    }

    [Fact]
    public void TieredClientTest()
    {
        var tieredClient = new TieredClient();
        Assert.Equal(0, tieredClient.Id);
        tieredClient.ClientName = "Client1";
        tieredClient.ClientId = Guid.NewGuid().ToString();
        tieredClient.IdPBaseUrl = "https://idp1.net";
        tieredClient.RedirectUri = "https://localhost/redirect";
        tieredClient.ClientUriSan = "https://localhost/";
        tieredClient.CommunityId = 10;
        tieredClient.Enabled = true;
        tieredClient.TokenEndpoint = "https://idp1.net/token";
    }

    [Fact]
    public void DuplicateCommunityException_SetsMessage()
    {
        var exception = new DuplicateCommunityException("Community already exists");

        Assert.Equal("Community already exists", exception.Message);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void DuplicateAnchorException_SetsMessage()
    {
        var exception = new DuplicateAnchorException("Anchor already exists");

        Assert.Equal("Anchor already exists", exception.Message);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void DuplicateIntermediateCertificateException_SetsMessage()
    {
        var exception = new DuplicateIntermediateCertificateException("Intermediate already exists");

        Assert.Equal("Intermediate already exists", exception.Message);
        Assert.IsAssignableFrom<Exception>(exception);
    }
}

