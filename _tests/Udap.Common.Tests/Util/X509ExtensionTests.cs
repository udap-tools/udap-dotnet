using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Udap.Util.Extensions;

namespace Udap.Common.Tests.Util;

public class X509ExtensionTests
{
    private string CertStore = "../../../../Udap.PKI.Generator/certstores";

    [Fact]
    public void ResolveUriSubjAltNameTest()
    {
        var certificate = new X509Certificate2($"{CertStore}/localhost_fhirlabs_community1/issued/fhirLabsApiClientLocalhostCert.cer");

        // Both should succeed.
        // The C# code cannot generated a SAN without the trailing slash on a URI without a path.
        // TODO: Need to consider issuing a PR to correct MS code base.  I think asp.net is the place.
        // But regardless I think Postels law applies here.
        certificate.ResolveUriSubjAltName("https://localhost:5055").Should().Be("https://localhost:5055/");
        certificate.ResolveUriSubjAltName("https://localhost:5055/").Should().Be("https://localhost:5055/");
        
        
        certificate.ResolveUriSubjAltName("https://localhost:7016/fhir/r4").Should().Be("https://localhost:7016/fhir/r4");
        certificate.ResolveUriSubjAltName("https://localhost:7016/fhir/r4/").Should().Be("https://localhost:7016/fhir/r4");
    }

    [Fact]
    public void KeyUsageTest()
    {
        var certificate = new X509Certificate2($"CertStore/anchors/SureFhirLabs_CA.cer");

        var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
        extensions.Should().NotBeNullOrEmpty();

        extensions.Single().KeyUsages.ToKeyUsageToString().Should().ContainInOrder("CrlSign", "KeyCertSign");
    }
}
