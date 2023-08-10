using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Udap.Util.Extensions;

namespace Udap.Common.Tests.Util;

public class X509ExtensionTests
{
    private string CertStore = "../../../../Udap.PKI.Generator/certstores";

    [Fact]
    public void ResolveUriSubjAltName()
    {
        var certificate = new X509Certificate2($"{CertStore}/surefhirlabs_community/issued/idp1.securedcontrols.net.server.cer");

        // Both should succeed.
        // The C# code cannot generated a SAN without the trailing slash on a URI without a path.
        // TODO: Need to consider issuing a PR to correct MS code base.  I think asp.net is the place.
        // But regardless I think Postels law applies here.
        certificate.ResolveUriSubjAltName("https://localhost:5055").Should().Be("https://localhost:5055/");
        certificate.ResolveUriSubjAltName("https://localhost:5055/").Should().Be("https://localhost:5055/");

        certificate.ResolveUriSubjAltName("https://idp1.securedcontrols.net:5055").Should().Be("https://idp1.securedcontrols.net:5055/");
        certificate.ResolveUriSubjAltName("https://idp1.securedcontrols.net:5055/").Should().Be("https://idp1.securedcontrols.net:5055/");


        certificate = new X509Certificate2($"{CertStore}/surefhirlabs_community/issued/fhirlabs.net.client.cer");
        certificate.ResolveUriSubjAltName("https://fhirlabs.net:7016/fhir/r4").Should().Be("https://fhirlabs.net:7016/fhir/r4");
        certificate.ResolveUriSubjAltName("https://fhirlabs.net:7016/fhir/r4/").Should().Be("https://fhirlabs.net:7016/fhir/r4");
    }
}
