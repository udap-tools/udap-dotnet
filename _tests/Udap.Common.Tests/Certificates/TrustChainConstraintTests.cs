#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Xunit.Abstractions;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Udap.Common.Tests.Certificates;

/// <summary>
/// Key usage, name constraints and critical extensions in chain validation (RFC 5280 sections 4.2, 4.2.1.3, 4.2.1.10).
/// </summary>
public class TrustChainConstraintTests
{
    private static readonly IEnumerable<Anchor>? NoAnchors = null;

    private readonly ITestOutputHelper _testOutputHelper;

    public TrustChainConstraintTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task Leaf_inside_the_root_name_constraints_is_trusted()
    {
        var root = CreateCa("CN=Constrained Root", null, permittedUriHost: "fhirlabs.net");
        var intermediate = CreateCa("CN=Constrained Intermediate", root);
        var leaf = CreateLeaf("CN=Leaf", intermediate, san: "https://fhirlabs.net/fhir/r4");

        var result = await CreateValidator().IsTrustedCertificateAsync("test", leaf, new X509Certificate2Collection(intermediate), new X509Certificate2Collection(root), NoAnchors);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Leaf_outside_the_root_name_constraints_is_rejected()
    {
        var root = CreateCa("CN=Constrained Root", null, permittedUriHost: "fhirlabs.net");
        var intermediate = CreateCa("CN=Constrained Intermediate", root);
        var leaf = CreateLeaf("CN=Leaf", intermediate, san: "https://evil.example/fhir/r4");

        var result = await CreateValidator().IsTrustedCertificateAsync("test", leaf, new X509Certificate2Collection(intermediate), new X509Certificate2Collection(root), NoAnchors);

        Assert.False(result.IsValid);
        Assert.Contains(result.ChainElements[0].Problems, p => p.Status == ChainProblemStatus.NameConstraintViolation);
    }

    [Fact]
    public async Task Intermediate_without_keyCertSign_is_rejected()
    {
        var root = CreateCa("CN=Root", null);
        var intermediate = CreateCa("CN=Intermediate", root, keyUsage: X509KeyUsageFlags.DigitalSignature);
        var leaf = CreateLeaf("CN=Leaf", intermediate, san: "https://fhirlabs.net/fhir/r4");

        var result = await CreateValidator().IsTrustedCertificateAsync("test", leaf, new X509Certificate2Collection(intermediate), new X509Certificate2Collection(root), NoAnchors);

        Assert.False(result.IsValid);
        Assert.Contains(result.ChainElements[1].Problems, p => p.Status == ChainProblemStatus.InvalidKeyUsage);
    }

    [Fact]
    public async Task Leaf_without_digitalSignature_is_rejected()
    {
        var root = CreateCa("CN=Root", null);
        var leaf = CreateLeaf("CN=Leaf", root, san: "https://fhirlabs.net/fhir/r4", keyUsage: X509KeyUsageFlags.KeyEncipherment);

        var result = await CreateValidator().IsTrustedCertificateAsync("test", leaf, null, new X509Certificate2Collection(root), NoAnchors);

        Assert.False(result.IsValid);
        Assert.Contains(result.ChainElements[0].Problems, p => p.Status == ChainProblemStatus.InvalidKeyUsage);
    }

    [Fact]
    public async Task Leaf_with_an_unknown_critical_extension_is_rejected()
    {
        var root = CreateCa("CN=Root", null);
        var leaf = CreateLeaf("CN=Leaf", root, san: "https://fhirlabs.net/fhir/r4",
            extra: new X509Extension(new Oid("1.3.6.1.4.1.99999.1"), new byte[] { 0x05, 0x00 }, critical: true));

        var result = await CreateValidator().IsTrustedCertificateAsync("test", leaf, null, new X509Certificate2Collection(root), NoAnchors);

        Assert.False(result.IsValid);
        Assert.Contains(result.ChainElements[0].Problems, p => p.Status == ChainProblemStatus.UnsupportedCriticalExtension);
    }

    [Fact]
    public async Task Leaf_with_an_unknown_non_critical_extension_is_trusted()
    {
        var root = CreateCa("CN=Root", null);
        var leaf = CreateLeaf("CN=Leaf", root, san: "https://fhirlabs.net/fhir/r4",
            extra: new X509Extension(new Oid("1.3.6.1.4.1.99999.1"), new byte[] { 0x05, 0x00 }, critical: false));

        var result = await CreateValidator().IsTrustedCertificateAsync("test", leaf, null, new X509Certificate2Collection(root), NoAnchors);

        Assert.True(result.IsValid);
    }

    private static X509Certificate2 CreateCa(
        string subject,
        X509Certificate2? issuer,
        string? permittedUriHost = null,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (permittedUriHost != null)
        {
            var permitted = new DerSequence(new GeneralSubtree(new GeneralName(GeneralName.UniformResourceIdentifier, permittedUriHost)));
            var nameConstraints = new DerSequence(new DerTaggedObject(false, 0, permitted));
            request.CertificateExtensions.Add(new X509Extension(new Oid(X509Extensions.NameConstraints.Id), nameConstraints.GetDerEncoded(), true));
        }

        if (issuer == null)
        {
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }

        using var cert = request.Create(issuer, issuer.NotBefore, issuer.NotAfter.AddDays(-1), RandomNumberGenerator.GetBytes(8));
        return cert.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 CreateLeaf(
        string subject,
        X509Certificate2 issuer,
        string san,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature,
        X509Extension? extra = null)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri(san));
        request.CertificateExtensions.Add(sanBuilder.Build());

        if (extra != null)
        {
            request.CertificateExtensions.Add(extra);
        }

        // Signed with the issuer's key directly: CertificateRequest.Create(issuer, ...) refuses an issuer whose
        // key usage lacks keyCertSign, which one test needs.
        var generator = X509SignatureGenerator.CreateForRSA(issuer.GetRSAPrivateKey()!, RSASignaturePadding.Pkcs1);
        return request.Create(issuer.SubjectName, generator, issuer.NotBefore, issuer.NotAfter.AddDays(-1), RandomNumberGenerator.GetBytes(8));
    }

    private TrustChainValidator CreateValidator()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var logger = services.BuildServiceProvider().GetRequiredService<ILogger<TrustChainValidator>>();

        return new TrustChainValidator(TrustChainValidator.DefaultProblemFlags, false, logger);
    }
}
