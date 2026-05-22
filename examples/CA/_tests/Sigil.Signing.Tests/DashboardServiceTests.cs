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

public class DashboardServiceTests
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory = new TestDbContextFactory();

    private DashboardService CreateService() =>
        new(_dbFactory, NullLogger<DashboardService>.Instance);

    [Fact]
    public async Task GetDashboard_EmptyDb_ReturnsZeroCounts()
    {
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainCount.ShouldBe(0);
        data.CaCertCount.ShouldBe(0);
        data.IssuedCertCount.ShouldBe(0);
        data.TemplateCount.ShouldBe(0);
        data.RevokedCertCount.ShouldBe(0);
        data.TrustDomainSummaries.ShouldBeEmpty();
        data.ExpiringCerts.ShouldBeEmpty();
        data.ExpiredCerts.ShouldBeEmpty();
        data.OverdueCrls.ShouldBeEmpty();
    }

    [Fact]
    public async Task GetDashboard_WithData_ReturnsCounts()
    {
        await SeedTrustDomainWithCertsAsync();
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainCount.ShouldBe(1);
        data.CaCertCount.ShouldBe(1);
        data.IssuedCertCount.ShouldBe(1);
    }

    [Fact]
    public async Task GetDashboard_ExpiredCert_AppearsInExpiredList()
    {
        await SeedTrustDomainWithCertsAsync(caNotAfter: DateTime.UtcNow.AddDays(-1));
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.ExpiredCerts.Where(c => c.CertType == "CA").ShouldHaveSingleItem();
    }

    [Fact]
    public async Task GetDashboard_ExpiringCert_AppearsInExpiringList()
    {
        await SeedTrustDomainWithCertsAsync(caNotAfter: DateTime.UtcNow.AddDays(30));
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.ExpiringCerts.Where(c => c.CertType == "CA").ShouldHaveSingleItem();
    }

    [Fact]
    public async Task GetDashboard_TrustDomainSummary_AggregatesCorrectly()
    {
        await SeedTrustDomainWithCertsAsync();
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainSummaries.ShouldHaveSingleItem();
        var summary = data.TrustDomainSummaries[0];
        summary.CaCount.ShouldBe(1);
        summary.IssuedCount.ShouldBe(1);
        summary.Name.ShouldBe("Test TrustDomain");
    }

    [Fact]
    public async Task GetDashboard_RevokedCert_CountedCorrectly()
    {
        await SeedTrustDomainWithCertsAsync(issuedRevoked: true);
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.RevokedCertCount.ShouldBe(1);
    }

    private async Task SeedTrustDomainWithCertsAsync(
        DateTime? caNotAfter = null,
        bool issuedRevoked = false)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();

        var trustDomain = new TrustDomain { Name = "Test TrustDomain", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "Test-CA",
            Subject = "CN=Test CA",
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = DateTime.UtcNow.AddDays(-1),
            NotAfter = caNotAfter ?? DateTime.UtcNow.AddYears(1)
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        var issued = new IssuedCertificate
        {
            IssuingCaCertificateId = ca.Id,
            Name = "Test-Issued",
            Subject = "CN=Test Issued",
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = "AABB" + cert.Thumbprint[4..],
            SerialNumber = "002",
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = DateTime.UtcNow.AddDays(-1),
            NotAfter = DateTime.UtcNow.AddYears(1),
            IsRevoked = issuedRevoked,
            RevokedAt = issuedRevoked ? DateTime.UtcNow : null
        };
        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();
    }
}
