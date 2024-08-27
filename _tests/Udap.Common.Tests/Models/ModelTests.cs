#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Udap.Common.Models;

namespace Udap.Common.Tests.Models;

public class ModelTests
{

    [Fact]
    public void SimpleAnchorTest()
    {
        var certificate = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");

        var anchor = new Anchor(certificate, "community1");

        anchor.Equals(anchor).Should().BeTrue();
        anchor.Equals(anchor as object).Should().BeTrue();

        var secondAnchor = new Anchor(certificate, "community2");
        anchor.Equals(secondAnchor).Should().BeFalse();
        anchor.Equals(secondAnchor as object).Should().BeFalse();

        anchor.Equals(new object()).Should().BeFalse();
        anchor.Equals(null).Should().BeFalse();
        anchor!.Equals(null as Anchor).Should().BeFalse();

        anchor.EndDate.Should().Be(certificate.NotAfter);
        anchor.BeginDate.Should().Be(certificate.NotBefore);
        anchor.Enabled.Should().BeFalse();
        anchor.Id.Should().Be(0);

        anchor.ToString().Should().Contain("Name CN=SureFhir-CA, OU=Root, O=Fhir Coding, L=Portland, S=Oregon, C=US | Community community1");

        anchor.GetHashCode().Should().NotBe(secondAnchor.GetHashCode());
    }

    [Fact]
    public void IntermediateTest()
    {
        var intermediateCertificate = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

        var intermediate = new Intermediate(intermediateCertificate);

        intermediate.Equals(intermediate).Should().BeTrue();
        intermediate.Equals(intermediate as object).Should().BeTrue();

        var secondAnchor = new Anchor(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer"));
        intermediate.Equals(secondAnchor).Should().BeFalse();
        intermediate.Equals(secondAnchor as object).Should().BeFalse();

        intermediate.Equals(new object()).Should().BeFalse();
        intermediate.Equals(null).Should().BeFalse();
        intermediate.Equals(null as Anchor).Should().BeFalse();

        intermediate.EndDate.Should().Be(intermediateCertificate.NotAfter);
        intermediate.BeginDate.Should().Be(intermediateCertificate.NotBefore);
        intermediate.Enabled.Should().BeFalse();
        intermediate.Id.Should().Be(0);

        intermediate.ToString().Should().Contain("| Name CN=SureFhir-Intermediate, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US");

        var anchorCertificate = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        intermediate.Anchor = new Anchor(anchorCertificate);
        intermediate.AnchorId.Should().Be(0);
        intermediate.Anchor.Thumbprint.Should().NotBeNullOrWhiteSpace();

        var secondIntermediate = new Intermediate(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer"));
        intermediate.GetHashCode().Should().NotBe(secondIntermediate.GetHashCode());
    }

    [Fact]
    public void IssuedCertificateTest()
    {
        var issuedCertificate = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var issued = new IssuedCertificate(issuedCertificate);

        issued.Equals(issued).Should().BeTrue();
        issued.Equals(issued as object).Should().BeTrue();

        var secondIssued = new IssuedCertificate(issuedCertificate, "community2");
        issued.Equals(secondIssued).Should().BeFalse();
        issued.Equals(secondIssued as object).Should().BeFalse();

        issued.Equals(new object()).Should().BeFalse();
        issued.Equals(null).Should().BeFalse();
        issued!.Equals(null as IssuedCertificate).Should().BeFalse();

        issued.GetHashCode().Should().NotBe(secondIssued.GetHashCode());
    }


    [Fact]
    public void SimpleCommunityTest()
    {
        var community = new Community();
        community.Default = true;
        community.Anchors = new List<Anchor>();
        community.Anchors.Add(new Anchor(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer")));
        community.Anchors.Add(new Anchor(new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer")));
        community.Certifications = new List<Certification>();
        community.Certifications.Add(new Certification());
        community.Certifications.Add(new Certification());

        community.Id.Should().Be(0);
        community.Anchors.Count.Should().Be(2);
        community.Certifications.Count.Should().Be(2);
        community.Default.Should().BeTrue();
    }

    [Fact]
    public void SimpleCertificationTest()
    {
        var certification = new Certification();
        certification.Id.Should().Be(0);
        certification.Name = "Cert1";
        certification.Name.Should().Be("Cert1");
    }

    [Fact]
    public void TieredClientTest()
    {
        var tieredClient = new TieredClient();
        tieredClient.Id.Should().Be(0);
        tieredClient.ClientName = "Client1";
        tieredClient.ClientId = Guid.NewGuid().ToString();
        tieredClient.IdPBaseUrl = "https://idp1.net";
        tieredClient.RedirectUri = "https://localhost/redirect";
        tieredClient.ClientUriSan = "https://localhost/";
        tieredClient.CommunityId = 10;
        tieredClient.Enabled = true;
        tieredClient.TokenEndpoint = "https://idp1.net/token";
    }
}

