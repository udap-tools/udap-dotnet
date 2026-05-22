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
using Shouldly;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services;

namespace Sigil.Signing.Tests;

public class CertificateExportServiceTests : IDisposable
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;

    public CertificateExportServiceTests()
    {
        _dbFactory = new TestDbContextFactory();
    }

    private CertificateExportService CreateService() =>
        new(_dbFactory, NullLogger<CertificateExportService>.Instance);

    [Fact]
    public async Task ExportPrivateKeyPem_Rsa_ReturnsPkcs8Pem()
    {
        var (caId, _) = await SeedCaCertificateAsync("RSA", 2048);
        var service = CreateService();

        var result = await service.ExportPrivateKeyPemAsync(caId, "CaCertificate");

        result.Success.ShouldBeTrue();
        result.Pem.ShouldStartWith("-----BEGIN PRIVATE KEY-----");
        result.Pem.ShouldEndWith("-----END PRIVATE KEY-----");
    }

    [Fact]
    public async Task ExportPrivateKeyPem_Ecdsa_ReturnsPkcs8Pem()
    {
        var (caId, _) = await SeedCaCertificateAsync("ECDSA", 384);
        var service = CreateService();

        var result = await service.ExportPrivateKeyPemAsync(caId, "CaCertificate");

        result.Success.ShouldBeTrue();
        result.Pem.ShouldStartWith("-----BEGIN PRIVATE KEY-----");
        result.Pem.ShouldEndWith("-----END PRIVATE KEY-----");
    }

    [Fact]
    public async Task ExportPrivateKeyPem_IssuedCertificate_Works()
    {
        var issuedId = await SeedIssuedCertificateAsync("RSA", 2048);
        var service = CreateService();

        var result = await service.ExportPrivateKeyPemAsync(issuedId, "IssuedCertificate");

        result.Success.ShouldBeTrue();
        result.Pem.ShouldContain("BEGIN PRIVATE KEY");
    }

    [Fact]
    public async Task ExportPrivateKeyPem_RoundTrips_CanSignAndVerify()
    {
        var (caId, cert) = await SeedCaCertificateAsync("RSA", 2048);
        var service = CreateService();

        var result = await service.ExportPrivateKeyPemAsync(caId, "CaCertificate");

        result.Success.ShouldBeTrue();

        using var reimported = RSA.Create();
        reimported.ImportFromPem(result.Pem);
        var testData = "round trip test"u8.ToArray();
        var signature = reimported.SignData(testData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var publicKey = cert.GetRSAPublicKey()!;
        publicKey.VerifyData(testData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .ShouldBeTrue();

        cert.Dispose();
    }

    [Fact]
    public async Task ExportPrivateKeyPem_NoPfxBytes_ReturnsFailure()
    {
        var caId = await SeedCaCertificateWithoutKeyAsync();
        var service = CreateService();

        var result = await service.ExportPrivateKeyPemAsync(caId, "CaCertificate");

        result.Success.ShouldBeFalse();
        result.Error.ShouldContain("No private key");
    }

    [Fact]
    public async Task ExportPrivateKeyPem_NonexistentId_ReturnsFailure()
    {
        var service = CreateService();

        var result = await service.ExportPrivateKeyPemAsync(99999, "CaCertificate");

        result.Success.ShouldBeFalse();
        result.Error.ShouldContain("not found");
    }

    [Fact]
    public async Task ExportPrivateKeyPem_CloudKmsLevel_ReturnsFailure()
    {
        var (caId, _) = await SeedCaCertificateAsync("RSA", 2048, securityLevel: CertSecurityLevel.CloudKms);
        var service = CreateService();

        var result = await service.ExportPrivateKeyPemAsync(caId, "CaCertificate");

        result.Success.ShouldBeFalse();
        result.Error.ShouldContain("security level");
    }

    [Fact]
    public async Task ExportPrivateKeyPem_Fips1403Level_ReturnsFailure()
    {
        var (caId, _) = await SeedCaCertificateAsync("RSA", 2048, securityLevel: CertSecurityLevel.Fips1403);
        var service = CreateService();

        var result = await service.ExportPrivateKeyPemAsync(caId, "CaCertificate");

        result.Success.ShouldBeFalse();
        result.Error.ShouldContain("security level");
    }

    [Fact]
    public async Task ExportCertificateDerBase64_ReturnsValidBase64()
    {
        var (caId, cert) = await SeedCaCertificateAsync("RSA", 2048);
        var service = CreateService();

        var result = await service.ExportCertificateDerBase64Async(caId, "CaCertificate");

        result.Success.ShouldBeTrue();
        var derBytes = Convert.FromBase64String(result.Pem!);
        derBytes.ShouldNotBeEmpty();

        using var roundTripped = X509CertificateLoader.LoadCertificate(derBytes);
        roundTripped.Thumbprint.ShouldBe(cert.Thumbprint);
        cert.Dispose();
    }

    [Fact]
    public async Task ExportCertificateDerBase64_IssuedCertificate_Works()
    {
        var issuedId = await SeedIssuedCertificateAsync("RSA", 2048);
        var service = CreateService();

        var result = await service.ExportCertificateDerBase64Async(issuedId, "IssuedCertificate");

        result.Success.ShouldBeTrue();
        var derBytes = Convert.FromBase64String(result.Pem!);
        derBytes.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task ExportCertificateDerBase64_NonexistentId_ReturnsFailure()
    {
        var service = CreateService();

        var result = await service.ExportCertificateDerBase64Async(99999, "CaCertificate");

        result.Success.ShouldBeFalse();
        result.Error.ShouldContain("not found");
    }

    #region Helpers

    private async Task<(int CaId, X509Certificate2 Cert)> SeedCaCertificateAsync(
        string algorithm, int keySize,
        CertSecurityLevel securityLevel = CertSecurityLevel.Software)
    {
        var password = "test-password";
        X509Certificate2 cert;

        if (algorithm == "ECDSA")
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            var req = new CertificateRequest("CN=Test ECDSA CA", ecdsa, HashAlgorithmName.SHA384);
            cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        }
        else
        {
            using var rsa = RSA.Create(keySize);
            var req = new CertificateRequest("CN=Test RSA CA", rsa, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        }

        var pfxBytes = cert.Export(X509ContentType.Pkcs12, password);

        await using var db = await _dbFactory.CreateDbContextAsync();
        var ca = new CaCertificate
        {
            Name = $"Test-{algorithm}-CA",
            X509CertificatePem = cert.ExportCertificatePem(),
            EncryptedPfxBytes = pfxBytes,
            PfxPassword = password,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = algorithm,
            KeySize = keySize,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            CertSecurityLevel = securityLevel,
            TrustDomainId = 1
        };

        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        return (ca.Id, cert);
    }

    private async Task<int> SeedIssuedCertificateAsync(string algorithm, int keySize)
    {
        var password = "test-password";
        using var rsa = RSA.Create(keySize);
        var req = new CertificateRequest("CN=Test Issued Cert", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var pfxBytes = cert.Export(X509ContentType.Pkcs12, password);

        await using var db = await _dbFactory.CreateDbContextAsync();
        var issued = new IssuedCertificate
        {
            Name = "Test-Issued",
            X509CertificatePem = cert.ExportCertificatePem(),
            EncryptedPfxBytes = pfxBytes,
            PfxPassword = password,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = algorithm,
            KeySize = keySize,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            IssuingCaCertificateId = 1
        };

        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();

        return issued.Id;
    }

    private async Task<int> SeedCaCertificateWithoutKeyAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=No Key CA", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        var ca = new CaCertificate
        {
            Name = "No-Key-CA",
            X509CertificatePem = cert.ExportCertificatePem(),
            EncryptedPfxBytes = null,
            PfxPassword = null,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            TrustDomainId = 1
        };

        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        return ca.Id;
    }

    public void Dispose()
    {
    }

    #endregion

}
