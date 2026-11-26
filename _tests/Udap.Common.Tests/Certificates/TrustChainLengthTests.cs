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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Xunit.Abstractions;

namespace Udap.Common.Tests.Certificates;

/// <summary>
/// The optional maximum chain length (global and per community) and the pathLenConstraint of intermediates.
/// </summary>
public class TrustChainLengthTests
{
    private const string CommunityA = "urn:oid:1.2.3.4.5.1";
    private const string CommunityB = "urn:oid:1.2.3.4.5.2";

    private readonly ITestOutputHelper _testOutputHelper;

    public TrustChainLengthTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    /// <summary>Root -> intermediate 1 -> intermediate 2 -> leaf: four certificates, one more than root -> intermediate -> leaf.</summary>
    private sealed record Pki(X509Certificate2 Root, X509Certificate2 Intermediate1, X509Certificate2 Intermediate2, X509Certificate2 Leaf)
    {
        public X509Certificate2Collection Intermediates => new(new[] { Intermediate1, Intermediate2 });
        public X509Certificate2Collection Anchors => new(Root);
    }

    private static Pki BuildFourCertificateChain(int? intermediate1PathLen = null)
    {
        var root = CreateCa("CN=Chain Length Root", issuer: null, pathLen: null);
        var intermediate1 = CreateCa("CN=Chain Length Intermediate 1", root, intermediate1PathLen);
        var intermediate2 = CreateCa("CN=Chain Length Intermediate 2", intermediate1, pathLen: null);
        var leaf = CreateLeaf("CN=Chain Length Leaf", intermediate2);

        return new Pki(root, intermediate1, intermediate2, leaf);
    }

    [Fact]
    public async Task ChainOneLevelTooLong_IsAccepted_WhenNoLimitIsSet()
    {
        var pki = BuildFourCertificateChain();
        var validator = CreateValidator(options: null);

        var result = await validator.IsTrustedCertificateAsync("test", pki.Leaf, pki.Intermediates, pki.Anchors);

        Assert.True(result);
    }

    [Fact]
    public async Task ChainOneLevelTooLong_IsAccepted_WithEmptyOptions()
    {
        var pki = BuildFourCertificateChain();
        var validator = CreateValidator(new TrustChainValidatorOptions());

        var result = await validator.IsTrustedCertificateAsync("test", pki.Leaf, pki.Intermediates, pki.Anchors);

        Assert.True(result);
    }

    [Fact]
    public async Task ChainOneLevelTooLong_IsRejected_WhenGlobalLimitIsSet()
    {
        var pki = BuildFourCertificateChain();
        var validator = CreateValidator(new TrustChainValidatorOptions { MaxChainLength = 3 });
        var problems = new List<ChainElementInfo>();
        validator.Problem += problems.Add;

        var result = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, new[] { new Anchor(pki.Root, CommunityA) });

        Assert.False(result.IsValid);
        Assert.Equal(4, result.ChainElements.Count);
        Assert.Contains(result.ChainElements[0].Problems, p => p.Status == ChainProblemStatus.ChainLengthExceeded);
        Assert.Contains(problems, e => e.Problems.Any(p => p.Status == ChainProblemStatus.ChainLengthExceeded));
    }

    [Fact]
    public async Task ChainAtTheLimit_IsAccepted()
    {
        var pki = BuildFourCertificateChain();
        var validator = CreateValidator(new TrustChainValidatorOptions { MaxChainLength = 4 });

        var result = await validator.IsTrustedCertificateAsync("test", pki.Leaf, pki.Intermediates, pki.Anchors);

        Assert.True(result);
    }

    [Fact]
    public async Task ChainLengthLimit_FailsValidation_EvenWhenNotAmongProblemFlags()
    {
        var pki = BuildFourCertificateChain();
        var validator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid,
            false,
            CreateLogger(),
            null,
            null,
            TrustChainValidator.DefaultDownloadTimeout,
            new TrustChainValidatorOptions { MaxChainLength = 3 });

        var result = await validator.IsTrustedCertificateAsync("test", pki.Leaf, pki.Intermediates, pki.Anchors);

        Assert.False(result);
    }

    [Fact]
    public async Task CommunityLimit_AppliesToTheCommunityOfTheMatchedAnchor()
    {
        var pki = BuildFourCertificateChain();
        var validator = CreateValidator(new TrustChainValidatorOptions
        {
            Communities = { new CommunityChainPolicy { Community = CommunityA, MaxChainLength = 3 } }
        });

        var inCommunityA = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, new[] { new Anchor(pki.Root, CommunityA) });
        var inCommunityB = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, new[] { new Anchor(pki.Root, CommunityB) });

        Assert.False(inCommunityA.IsValid);
        Assert.Equal(CommunityA, inCommunityA.CommunityName);
        Assert.Contains(inCommunityA.ChainElements[0].Problems, p => p.Status == ChainProblemStatus.ChainLengthExceeded);
        Assert.True(inCommunityB.IsValid);
    }

    [Fact]
    public async Task CommunityLimit_UsesTheExplicitCommunityName_WhenNoAnchorModelsAreGiven()
    {
        var pki = BuildFourCertificateChain();
        var validator = CreateValidator(new TrustChainValidatorOptions
        {
            Communities = { new CommunityChainPolicy { Community = CommunityA, MaxChainLength = 3 } }
        });

        var inCommunityA = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, null, CommunityA);
        var inCommunityB = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, null, CommunityB);
        var unknownCommunity = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, null);

        Assert.False(inCommunityA.IsValid);
        Assert.True(inCommunityB.IsValid);
        Assert.True(unknownCommunity.IsValid);
    }

    [Fact]
    public async Task CommunityEntry_OverridesTheGlobalLimit()
    {
        var pki = BuildFourCertificateChain();
        var validator = CreateValidator(new TrustChainValidatorOptions
        {
            MaxChainLength = 3,
            Communities =
            {
                new CommunityChainPolicy { Community = CommunityA, MaxChainLength = 4 },
                new CommunityChainPolicy { Community = CommunityB, MaxChainLength = 0 },
                new CommunityChainPolicy { Community = "urn:oid:1.2.3.4.5.3" }
            }
        });

        var inCommunityA = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, new[] { new Anchor(pki.Root, CommunityA) });
        var inCommunityB = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, new[] { new Anchor(pki.Root, CommunityB) });
        var otherCommunity = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, new[] { new Anchor(pki.Root, "urn:oid:1.2.3.4.5.3") });

        Assert.True(inCommunityA.IsValid);
        Assert.True(inCommunityB.IsValid);
        Assert.False(otherCommunity.IsValid);
    }

    [Fact]
    public async Task ResolvedFromDependencyInjection_ReadsConfiguredOptions()
    {
        var pki = BuildFourCertificateChain();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{TrustChainValidatorOptions.SectionName}:Communities:0:Community"] = CommunityA,
                [$"{TrustChainValidatorOptions.SectionName}:Communities:0:MaxChainLength"] = "3"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.Configure<TrustChainValidatorOptions>(configuration.GetSection(TrustChainValidatorOptions.SectionName));
        services.AddSingleton<TrustChainValidator>();
        var validator = services.BuildServiceProvider().GetRequiredService<TrustChainValidator>();

        Assert.NotNull(validator.Options);
        Assert.True(validator.Options.HasCommunityLimits);

        // The DI constructor checks revocation, and these in-memory certificates publish no CRL, so look only
        // at the chain-length problem here.
        var result = await validator.IsTrustedCertificateAsync(
            "test", pki.Leaf, pki.Intermediates, pki.Anchors, new[] { new Anchor(pki.Root, CommunityA) });

        Assert.False(result.IsValid);
        Assert.Contains(result.ChainElements[0].Problems, p => p.Status == ChainProblemStatus.ChainLengthExceeded);
    }

    [Fact]
    public async Task IntermediateWhosePathLenConstraintIsExceeded_IsRejected()
    {
        // Intermediate 1 allows no further intermediate below it, but issued intermediate 2.
        var pki = BuildFourCertificateChain(intermediate1PathLen: 0);
        var validator = CreateValidator(options: null);

        var result = await validator.IsTrustedCertificateAsync("test", pki.Leaf, pki.Intermediates, pki.Anchors, null);

        Assert.False(result.IsValid);
        Assert.Equal(4, result.ChainElements.Count);
        Assert.Contains(result.ChainElements[2].Problems, p => p.Status == ChainProblemStatus.PathLengthConstraintExceeded);
        Assert.DoesNotContain(result.ChainElements[2].Problems, p => p.Status == ChainProblemStatus.InvalidBasicConstraints);
        Assert.DoesNotContain(result.ChainElements[1].Problems, p => p.Status == ChainProblemStatus.PathLengthConstraintExceeded);
    }

    [Fact]
    public async Task PathLenConstraintCheck_CanBeMaskedWithCustomProblemFlags()
    {
        var pki = BuildFourCertificateChain(intermediate1PathLen: 0);
        var flagsWithoutPathLen = TrustChainValidator.DefaultProblemFlags & ~ChainProblemStatus.PathLengthConstraintExceeded;
        var validator = new TrustChainValidator(flagsWithoutPathLen, false, CreateLogger());

        var result = await validator.IsTrustedCertificateAsync("test", pki.Leaf, pki.Intermediates, pki.Anchors, null);

        // The violation is still reported on the chain element, but no longer fails validation.
        Assert.True(result.IsValid);
        Assert.Contains(result.ChainElements[2].Problems, p => p.Status == ChainProblemStatus.PathLengthConstraintExceeded);
    }

    [Fact]
    public void DefaultProblemFlags_IncludePathLengthConstraintExceeded()
    {
        Assert.True(TrustChainValidator.DefaultProblemFlags.HasFlag(ChainProblemStatus.PathLengthConstraintExceeded));
        Assert.True(TrustChainValidator.DefaultProblemFlags.HasFlag(ChainProblemStatus.InvalidBasicConstraints));
    }

    [Fact]
    public async Task IntermediateWhosePathLenConstraintIsMet_IsAccepted()
    {
        var pki = BuildFourCertificateChain(intermediate1PathLen: 1);
        var validator = CreateValidator(options: null);

        var result = await validator.IsTrustedCertificateAsync("test", pki.Leaf, pki.Intermediates, pki.Anchors);

        Assert.True(result);
    }

    [Fact]
    public async Task PathLenConstraintOfZero_AllowsIssuingTheLeaf()
    {
        var root = CreateCa("CN=PathLen Root", issuer: null, pathLen: null);
        var intermediate = CreateCa("CN=PathLen Intermediate", root, pathLen: 0);
        var leaf = CreateLeaf("CN=PathLen Leaf", intermediate);
        var validator = CreateValidator(options: null);

        var result = await validator.IsTrustedCertificateAsync(
            "test", leaf, new X509Certificate2Collection(intermediate), new X509Certificate2Collection(root));

        Assert.True(result);
    }

    [Theory]
    [InlineData(null, null, null)]
    [InlineData(3, null, 3)]
    [InlineData(3, CommunityB, 3)]
    [InlineData(3, CommunityA, 5)]
    [InlineData(0, null, null)]
    [InlineData(-1, null, null)]
    public void GetMaxChainLength_ResolvesTheLimitForACommunity(int? global, string? community, int? expected)
    {
        var options = new TrustChainValidatorOptions
        {
            MaxChainLength = global,
            Communities = { new CommunityChainPolicy { Community = CommunityA, MaxChainLength = 5 } }
        };

        Assert.Equal(expected, options.GetMaxChainLength(community));
    }

    private TrustChainValidator CreateValidator(TrustChainValidatorOptions? options)
    {
        return new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            false,
            CreateLogger(),
            null,
            null,
            TrustChainValidator.DefaultDownloadTimeout,
            options);
    }

    private ILogger<TrustChainValidator> CreateLogger()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        return services.BuildServiceProvider().GetRequiredService<ILogger<TrustChainValidator>>();
    }

    private static X509Certificate2 CreateCa(string subject, X509Certificate2? issuer, int? pathLen)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, pathLen.HasValue, pathLen ?? 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (issuer == null)
        {
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }

        using var cert = request.Create(issuer, issuer.NotBefore, issuer.NotAfter.AddDays(-1), RandomNumberGenerator.GetBytes(8));
        return cert.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 CreateLeaf(string subject, X509Certificate2 issuer)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        return request.Create(issuer, issuer.NotBefore, issuer.NotAfter.AddDays(-1), RandomNumberGenerator.GetBytes(8));
    }
}
