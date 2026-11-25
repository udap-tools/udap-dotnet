#region (c) 2023-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Models;
using Xunit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Udap.Server.Storage;
using Udap.Server.Storage.DbContexts;
using Udap.Server.Storage.Options;
using Udap.Server.Storage.Stores;

namespace UdapServer.Tests.EntityFramework.Stores;

public class UdapClientRegistrationStoreTests : StorageFixture<UdapClientRegistrationStoreTests, UdapDbContext, UdapConfigurationStoreOptions>
{
     public UdapClientRegistrationStoreTests(TestDatabaseProvider<UdapDbContext> fixture) : base(fixture)
    {
        foreach (var options in TestDatabaseProviders)
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
            RedirectUris = ["http://localhost"],
            AllowedGrantTypes = new List<string>
            {
                GrantType.AuthorizationCode
            },
            ClientSecrets = new List<Secret>
            {
                new Secret("http://localhost"){ Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME},
                new Secret("http://community_1"){ Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY}
            },
            Properties = new Dictionary<string, string>
            {
                {UdapServerConstants.ClientPropertyConstants.Organization, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap},
                {UdapServerConstants.ClientPropertyConstants.DataHolder, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap}
            }
        };

        await using var context = new UdapDbContext(options);
        var store = new UdapClientRegistrationStore(context, Substitute.For<ILogger<UdapClientRegistrationStore>>());
        var result = await store.UpsertClient(testClient);
        Assert.False(result);

        var client = await store.GetClient(testClient);
        Assert.NotNull(client);
        Assert.Equal(testClient.ClientId, client.ClientId);
        Assert.Equal("http://localhost", client.RedirectUris.Single());

        //
        // Re-register with different RedirectUrl
        //
        testClient.RedirectUris = ["http://localhost2"];
        result = await store.UpsertClient(testClient);
        Assert.True(result);
        client = await store.GetClient(testClient);
        Assert.NotNull(client);
        Assert.Equal(testClient.ClientId, client.ClientId);
        Assert.Equal("http://localhost2", client.RedirectUris.Single());
    }

    [Theory]
    [MemberData(nameof(TestDatabaseProviders))]
    public async Task UpsertTieredClient_DisableThenReRegister_StoresTheIdPsCurrentRegistration(DbContextOptions<UdapDbContext> options)
    {
        var idpBaseUrl = $"https://idp-{Guid.NewGuid():N}.example.com";

        await using var context = new UdapDbContext(options);
        var community = new Udap.Server.Storage.Entities.Community { Name = $"udap://{Guid.NewGuid():N}/", Enabled = true };
        context.Communities.Add(community);
        await context.SaveChangesAsync();

        var store = new UdapClientRegistrationStore(context, Substitute.For<ILogger<UdapClientRegistrationStore>>());

        Udap.Common.Models.TieredClient Registration(string clientId, string tokenEndpoint, bool enabled) => new()
        {
            ClientName = "AuthServer Client",
            ClientId = clientId,
            IdPBaseUrl = idpBaseUrl,
            RedirectUri = "https://client.example.com/callback",
            ClientUriSan = "https://auth.example.com",
            CommunityId = community.Id,
            Enabled = enabled,
            TokenEndpoint = tokenEndpoint
        };

        Assert.False(await store.UpsertTieredClient(Registration("first", "https://idp.example.com/connect/token", true)));

        // Disabled after invalid_client: everything else is kept.
        var disabled = (await store.FindTieredClientByIdPBaseUrl(idpBaseUrl))!;
        disabled.Enabled = false;
        Assert.True(await store.UpsertTieredClient(disabled));

        var stored = (await store.FindTieredClientByIdPBaseUrl(idpBaseUrl))!;
        Assert.False(stored.Enabled);
        Assert.Equal("first", stored.ClientId);
        Assert.Equal("https://idp.example.com/connect/token", stored.TokenEndpoint);

        // Registered again: the IdP issued a new client_id and token endpoint, and the row is enabled.
        var reRegistration = Registration("second", "https://idp.example.com/oauth/token", true);
        Assert.True(await store.UpsertTieredClient(reRegistration));
        Assert.Equal("second", reRegistration.ClientId);

        stored = (await store.FindTieredClientByIdPBaseUrl(idpBaseUrl))!;
        Assert.True(stored.Enabled);
        Assert.Equal("second", stored.ClientId);
        Assert.Equal("https://idp.example.com/oauth/token", stored.TokenEndpoint);
        Assert.Null(await store.FindTieredClientById("first"));
    }

    [Theory]
    [MemberData(nameof(TestDatabaseProviders))]
    public async Task ConcurrentRegistrationsOfTheSameClient_CreateOneClient(DbContextOptions<UdapDbContext> options)
    {
        var issuer = $"https://client.example.com/{Guid.NewGuid():N}";

        // Each registration request gets a new client_id, a new DbContext and a new store, as the endpoint does.
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(i => Task.Run(async () =>
        {
            await using var context = new UdapDbContext(options);
            var store = new UdapClientRegistrationStore(context, Substitute.For<ILogger<UdapClientRegistrationStore>>());

            return await store.UpsertClient(new Client
            {
                ClientId = $"concurrent_{Guid.NewGuid():N}",
                ClientName = "Concurrent Client",
                AllowedGrantTypes = new List<string> { GrantType.ClientCredentials },
                ClientSecrets = new List<Secret>
                {
                    new Secret(issuer) { Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME },
                    new Secret("http://community_1") { Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY }
                },
                Properties = new Dictionary<string, string>
                {
                    { UdapServerConstants.ClientPropertyConstants.Organization, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap },
                    { UdapServerConstants.ClientPropertyConstants.DataHolder, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap }
                }
            });
        })));

        Assert.Single(results, created => !created);

        await using var verify = new UdapDbContext(options);
        Assert.Equal(1, await verify.Clients.CountAsync(c => c.ClientSecrets.Any(s =>
            s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME && s.Value == issuer)));
    }

    [Theory]
    [MemberData(nameof(TestDatabaseProviders))]
    public async Task RegisterTwoCommunitiesWithSameISS_AndCancelOne(DbContextOptions<UdapDbContext> options)
    {
        var testClient_community1 = new Client
        {
            ClientId = "test_client_1",
            ClientName = "Test Client_1",
            RedirectUris = ["http://localhost"],
            AllowedGrantTypes = new List<string>
            {
                GrantType.AuthorizationCode
            },
            ClientSecrets = new List<Secret>
            {
                new Secret("http://localhost") { Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME },
                new Secret("http://community_1") { Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY }
            },
            Properties = new Dictionary<string, string>
            {
                {UdapServerConstants.ClientPropertyConstants.Organization, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap},
                {UdapServerConstants.ClientPropertyConstants.DataHolder, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap}
            }
        };

        var testClient_community2 = new Client
        {
            ClientId = "test_client_2",
            ClientName = "Test Client_2",
            RedirectUris = ["http://localhost2"],
            AllowedGrantTypes = new List<string>
            {
                GrantType.AuthorizationCode
            },
            ClientSecrets = new List<Secret>
            {
                new Secret("http://localhost"){ Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME},
                new Secret("http://community_2"){ Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY}
            },
            Properties = new Dictionary<string, string>
            {
                {UdapServerConstants.ClientPropertyConstants.Organization, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap},
                {UdapServerConstants.ClientPropertyConstants.DataHolder, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap}
            }
        };

        // First Register
        await using (var context = new UdapDbContext(options))
        {
            var store = new UdapClientRegistrationStore(context,
                Substitute.For<ILogger<UdapClientRegistrationStore>>());
            var result = await store.UpsertClient(testClient_community1);
            Assert.False(result);

            var client = await store.GetClient(testClient_community1);
            Assert.NotNull(client);
            Assert.Equal(testClient_community1.ClientId, client.ClientId);
            Assert.Equal("http://localhost", client.RedirectUris.Single());
        }

        // Second Register
        await using (var context = new UdapDbContext(options))
        {
            var store = new UdapClientRegistrationStore(context, Substitute.For<ILogger<UdapClientRegistrationStore>>());
            var result = await store.UpsertClient(testClient_community2);
            Assert.False(result);

            var client = await store.GetClient(testClient_community2);
            Assert.NotNull(client);
            Assert.Equal(testClient_community2.ClientId, client.ClientId);
            Assert.Equal("http://localhost2", client.RedirectUris.Single());
        }


        // Cancel Client 1
        await using (var context = new UdapDbContext(options))
        {
            testClient_community1.AllowedGrantTypes = new List<string>();

            var store = new UdapClientRegistrationStore(context,
                Substitute.For<ILogger<UdapClientRegistrationStore>>());
            var result = await store.CancelRegistration(testClient_community1);
            Assert.Equal(1, result);

            // Client 1 is deleted
            var client = await store.GetClient(testClient_community1);
            Assert.Null(client);

            // Client 2 still exists
            client = await store.GetClient(testClient_community2);
            Assert.NotNull(client);
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabaseProviders))]
    public async Task RegisterWithCertificateAndUpdateOnReRegistration(DbContextOptions<UdapDbContext> options)
    {
        using var cert1 = CreateSelfSignedCert("CN=TestClient1");
        var cert1Base64 = Convert.ToBase64String(cert1.Export(X509ContentType.Cert));

        var testClient = new Client
        {
            ClientId = "test_client_cert",
            ClientName = "Test Client With Cert",
            AllowedGrantTypes = new List<string> { GrantType.ClientCredentials },
            ClientSecrets = new List<Secret>
            {
                new Secret("http://localhost") { Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME, Expiration = cert1.NotAfter },
                new Secret("1") { Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY, Expiration = cert1.NotAfter },
                new Secret(cert1Base64) { Type = UdapServerConstants.SecretTypes.UDAP_X509_CERTIFICATE, Expiration = cert1.NotAfter }
            },
            Properties = new Dictionary<string, string>
            {
                { UdapServerConstants.ClientPropertyConstants.Organization, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap },
                { UdapServerConstants.ClientPropertyConstants.DataHolder, UdapServerConstants.ClientPropertyConstants.DefaultOrgMap }
            }
        };

        // Initial registration
        await using (var context = new UdapDbContext(options))
        {
            var store = new UdapClientRegistrationStore(context, Substitute.For<ILogger<UdapClientRegistrationStore>>());
            var result = await store.UpsertClient(testClient);
            Assert.False(result);
        }

        // Verify certificate was stored
        await using (var context = new UdapDbContext(options))
        {
            var entity = await context.Clients
                .Include(c => c.ClientSecrets)
                .SingleAsync(c => c.ClientId == testClient.ClientId);

            var certSecret = entity.ClientSecrets.SingleOrDefault(s => s.Type == UdapServerConstants.SecretTypes.UDAP_X509_CERTIFICATE);
            Assert.NotNull(certSecret);
            Assert.Equal(cert1Base64, certSecret.Value);
        }

        // Re-register with a new certificate
        using var cert2 = CreateSelfSignedCert("CN=TestClient2");
        var cert2Base64 = Convert.ToBase64String(cert2.Export(X509ContentType.Cert));

        testClient.ClientSecrets = new List<Secret>
        {
            new Secret("http://localhost") { Type = UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME, Expiration = cert2.NotAfter },
            new Secret("1") { Type = UdapServerConstants.SecretTypes.UDAP_COMMUNITY, Expiration = cert2.NotAfter },
            new Secret(cert2Base64) { Type = UdapServerConstants.SecretTypes.UDAP_X509_CERTIFICATE, Expiration = cert2.NotAfter }
        };

        await using (var context = new UdapDbContext(options))
        {
            var store = new UdapClientRegistrationStore(context, Substitute.For<ILogger<UdapClientRegistrationStore>>());
            var result = await store.UpsertClient(testClient);
            Assert.True(result);
        }

        // Verify certificate was updated
        await using (var context = new UdapDbContext(options))
        {
            var entity = await context.Clients
                .Include(c => c.ClientSecrets)
                .SingleAsync(c => c.ClientId == testClient.ClientId);

            var certSecret = entity.ClientSecrets.SingleOrDefault(s => s.Type == UdapServerConstants.SecretTypes.UDAP_X509_CERTIFICATE);
            Assert.NotNull(certSecret);
            Assert.Equal(cert2Base64, certSecret.Value);
        }
    }

    private static X509Certificate2 CreateSelfSignedCert(string subject)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
    }
}