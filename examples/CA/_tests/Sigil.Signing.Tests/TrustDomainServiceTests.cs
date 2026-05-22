#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Shouldly;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sigil.Common.Data;
using Sigil.Common.Services;

namespace Sigil.Signing.Tests;

public class TrustDomainServiceTests
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory = new TestDbContextFactory();

    private TrustDomainService CreateService() =>
        new(_dbFactory, NullLogger<TrustDomainService>.Instance);

    [Fact]
    public async Task GetAll_EmptyDb_ReturnsEmpty()
    {
        var service = CreateService();

        var result = await service.GetAllAsync();

        result.ShouldBeEmpty();
    }

    [Fact]
    public async Task CreateAsync_BasicTrustDomain_Persists()
    {
        var service = CreateService();

        var trustDomain = await service.CreateAsync("My TrustDomain", "A test trustDomain", []);

        trustDomain.Id.ShouldBeGreaterThan(0);
        trustDomain.Name.ShouldBe("My TrustDomain");

        var all = await service.GetAllAsync();
        all.ShouldHaveSingleItem();
        all[0].Name.ShouldBe("My TrustDomain");
        all[0].Description.ShouldBe("A test trustDomain");
    }

    [Fact]
    public async Task CreateAsync_WithBaseUrls_PersistsUrls()
    {
        var service = CreateService();

        var urls = new List<(string Url, string? PublishingBasePath)>
        {
            ("https://example.com/fhir", "/publish/path"),
            ("https://other.com/fhir", null)
        };

        await service.CreateAsync("URL TrustDomain", null, urls);

        var all = await service.GetAllAsync();
        all.ShouldHaveSingleItem();
        all[0].BaseUrls.Count.ShouldBe(2);
        all[0].BaseUrls[0].Url.ShouldBe("https://example.com/fhir");
        all[0].BaseUrls[0].PublishingBasePath.ShouldBe("/publish/path");
        all[0].BaseUrls[1].Url.ShouldBe("https://other.com/fhir");
    }

    [Fact]
    public async Task CreateAsync_TrimsNameAndUrl()
    {
        var service = CreateService();

        await service.CreateAsync("  Spaced  ", null, [("  https://example.com/  ", null)]);

        var all = await service.GetAllAsync();
        all[0].Name.ShouldBe("Spaced");
        all[0].BaseUrls[0].Url.ShouldBe("https://example.com");
    }

    [Fact]
    public async Task UpdateAsync_ChangesNameAndUrls()
    {
        var service = CreateService();
        var trustDomain = await service.CreateAsync("Original", null, [("https://old.com", null)]);

        await service.UpdateAsync(trustDomain.Id, "Renamed", "New desc",
            [("https://new.com", "/new/path")]);

        var all = await service.GetAllAsync();
        all.ShouldHaveSingleItem();
        all[0].Name.ShouldBe("Renamed");
        all[0].Description.ShouldBe("New desc");
        all[0].BaseUrls.ShouldHaveSingleItem();
        all[0].BaseUrls[0].Url.ShouldBe("https://new.com");
    }

    [Fact]
    public async Task DeleteAsync_RemovesTrustDomain()
    {
        var service = CreateService();
        var trustDomain = await service.CreateAsync("To Delete", null, []);

        await service.DeleteAsync(trustDomain.Id);

        var all = await service.GetAllAsync();
        all.ShouldBeEmpty();
    }

    [Fact]
    public async Task DeleteAsync_NonexistentId_DoesNotThrow()
    {
        var service = CreateService();

        var act = () => service.DeleteAsync(99999);

        await Should.NotThrowAsync(act);
    }

    [Fact]
    public async Task GetAll_OrdersByName()
    {
        var service = CreateService();
        await service.CreateAsync("Zebra", null, []);
        await service.CreateAsync("Alpha", null, []);
        await service.CreateAsync("Middle", null, []);

        var all = await service.GetAllAsync();

        all.Count.ShouldBe(3);
        all[0].Name.ShouldBe("Alpha");
        all[1].Name.ShouldBe("Middle");
        all[2].Name.ShouldBe("Zebra");
    }
}
