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
                new Secret("http://localhost"){ Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME},
                new Secret("http://community_1"){ Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY}
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

    [Theory]
    [MemberData(nameof(TestDatabaseProviders))]
    public async Task RegisterTwoCommunitiesWithSameISS_AndCancelOne(DbContextOptions<UdapDbContext> options)
    {
        var testClient_community1 = new Client
        {
            ClientId = "test_client_1",
            ClientName = "Test Client_1",
            RedirectUris = new[] { "http://localhost" },
            AllowedGrantTypes = new List<string>
            {
                GrantType.AuthorizationCode
            },
            ClientSecrets = new List<Secret>
            {
                new Secret("http://localhost") { Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME },
                new Secret("http://community_1") { Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY }
            }
        };

        var testClient_community2 = new Client
        {
            ClientId = "test_client_2",
            ClientName = "Test Client_2",
            RedirectUris = new[] { "http://localhost2" },
            AllowedGrantTypes = new List<string>
            {
                GrantType.AuthorizationCode
            },
            ClientSecrets = new List<Secret>
            {
                new Secret("http://localhost"){ Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME},
                new Secret("http://community_2"){ Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY}
            }
        };

        // First Register
        await using (var context = new UdapDbContext(options))
        {
            var store = new UdapClientRegistrationStore(context,
                new Mock<ILogger<UdapClientRegistrationStore>>().Object);
            var result = await store.UpsertClient(testClient_community1, default);
            result.Should().BeFalse();

            var client = await store.GetClient(testClient_community1);
            client.Should().NotBeNull();
            client!.ClientId.Should().Be(testClient_community1.ClientId);
            client.RedirectUris.Single().Should().Be("http://localhost");
        }

        // Second Register
        await using (var context = new UdapDbContext(options))
        {
            var store = new UdapClientRegistrationStore(context, new Mock<ILogger<UdapClientRegistrationStore>>().Object);
            var result = await store.UpsertClient(testClient_community2, default);
            result.Should().BeFalse();

            var client = await store.GetClient(testClient_community2);
            client.Should().NotBeNull();
            client!.ClientId.Should().Be(testClient_community2.ClientId);
            client.RedirectUris.Single().Should().Be("http://localhost2");
        }


        // Cancel Client 1
        await using (var context = new UdapDbContext(options))
        {
            testClient_community1.AllowedGrantTypes = new List<string>();

            var store = new UdapClientRegistrationStore(context,
                new Mock<ILogger<UdapClientRegistrationStore>>().Object);
            var result = await store.CancelRegistration(testClient_community1, default);
            // result.Should().Be(1);

            // Client 1 is deleted
            var client = await store.GetClient(testClient_community1);
            client.Should().BeNull();

            // Client 2 still exists
            client = await store.GetClient(testClient_community2);
            client.Should().NotBeNull();
        }
    }
}