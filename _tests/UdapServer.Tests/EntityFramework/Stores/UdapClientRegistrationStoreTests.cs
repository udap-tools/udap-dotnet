#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Models;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Udap.Server;
using Udap.Server.DbContexts;
using Udap.Server.Options;
using Udap.Server.Stores;

namespace UdapServer.Tests.EntityFramework.Stores;

public class UdapClientRegistrationStoreTests : StorageFixture<UdapClientRegistrationStoreTests, UdapDbContext, UdapConfigurationStoreOptions>
{
     public UdapClientRegistrationStoreTests(TestDatabaseProvider<UdapDbContext> fixture) : base(fixture)
    {
        foreach (var options in TestDatabaseProviders.SelectMany(x => x.Select(y => (DbContextOptions<UdapDbContext>)y)).ToList())
        {
            using var context = new UdapDbContext(options, true);
            context.Database.EnsureCreated();
        }
    }
    
    [Theory]
    [MemberData(nameof(TestDatabaseProviders))]
    public async Task RegisterWithUrlRedirectAndRegisterWithDifferentUrlRedirect(DbContextOptions<UdapDbContext> options)
    {
        var testClient = new Client
        {
            ClientId = "test_client",
            ClientName = "Test Client",
            RedirectUris = new[] { "http://localhost" },
            AllowedGrantTypes = new List<string>
            {
                GrantType.AuthorizationCode
            },
            ClientSecrets = new List<Secret>
            {
                new Secret("http://localhost"){ Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME}
            }
        };

        await using var context = new UdapDbContext(options);
        var store = new UdapClientRegistrationStore(context, new Mock<ILogger<UdapClientRegistrationStore>>().Object);
        var result = await store.UpsertClient(testClient, default);
        result.Should().BeFalse();

        var client = await store.GetClient(testClient);
        client.Should().NotBeNull();
        client!.ClientId.Should().Be(testClient.ClientId);
        client.RedirectUris.Single().Should().Be("http://localhost");

        //
        // Re-register with different RedirectUrl
        //
        testClient.RedirectUris = new[] { "http://localhost2" };
        result = await store.UpsertClient(testClient, default);
        result.Should().BeTrue();
        client = await store.GetClient(testClient);
        client.Should().NotBeNull();
        client!.ClientId.Should().Be(testClient.ClientId);
        client.RedirectUris.Single().Should().Be("http://localhost2");
    }
}