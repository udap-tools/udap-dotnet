#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Udap.Server.Storage.DbContexts;
using Udap.Server.Storage.Entities;
using Udap.Server.Stores;
using Udap.Util.Extensions;

namespace UdapServer.Tests.Stores;

public class UdapDbTrustAnchorStoreTests
{
    [Fact]
    public async Task Resolve_Returns_Only_Enabled_Anchors_With_Their_Community_And_Rereads_The_Database()
    {
        var services = new ServiceCollection();
        var databaseName = Guid.NewGuid().ToString();
        var databaseRoot = new InMemoryDatabaseRoot();
        services.AddUdapDbContext<UdapDbContext>(options =>
        {
            options.UdapDbContext = b => b.UseInMemoryDatabase(databaseName, databaseRoot);
        });
        var provider = services.BuildServiceProvider();

#if NET9_0_OR_GREATER
        var cert = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
#else
        var cert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
#endif

        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
            var enabledCommunity = new Community { Name = "udap://enabled.example", Enabled = true };
            var disabledCommunity = new Community { Name = "udap://disabled.example", Enabled = false };

            db.Communities.AddRange(enabledCommunity, disabledCommunity);
            db.Anchors.AddRange(
                NewAnchor(cert, "trusted", enabled: true, enabledCommunity),
                NewAnchor(cert, "anchor-disabled", enabled: false, enabledCommunity),
                NewAnchor(cert, "community-disabled", enabled: true, disabledCommunity));
            await db.SaveChangesAsync();
        }

        var store = new UdapDbTrustAnchorStore(provider.GetRequiredService<IServiceScopeFactory>());

        var resolved = await store.Resolve();

        var anchor = Assert.Single(resolved.AnchorCertificates);
        Assert.Equal("trusted", anchor.Name);
        Assert.Equal("udap://enabled.example", anchor.Community);

        // Disabling the anchor takes effect on the next Resolve, without a new store instance.
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<UdapDbContext>();
            var entity = await db.Anchors.SingleAsync(a => a.Name == "trusted");
            entity.Enabled = false;
            await db.SaveChangesAsync();
        }

        resolved = await store.Resolve();

        Assert.Empty(resolved.AnchorCertificates);
    }

    private static Anchor NewAnchor(X509Certificate2 cert, string name, bool enabled, Community community)
    {
        return new Anchor
        {
            Name = name,
            Enabled = enabled,
            X509Certificate = cert.ToPemFormat(),
            Thumbprint = cert.Thumbprint,
            BeginDate = cert.NotBefore.ToUniversalTime(),
            EndDate = cert.NotAfter.ToUniversalTime(),
            Community = community,
            Intermediates = new List<Intermediate>()
        };
    }
}
