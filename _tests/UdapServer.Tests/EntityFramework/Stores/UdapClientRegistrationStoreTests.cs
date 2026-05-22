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