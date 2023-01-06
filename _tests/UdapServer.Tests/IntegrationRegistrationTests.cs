#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Options;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using FluentAssertions;
using IdentityModel;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client.Messages;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Common.Registration;
using Udap.Idp;
using Udap.Server;
using Udap.Server.DbContexts;
using Udap.Server.Extensions;
using Udap.Server.Options;
using Udap.Server.Registration;
using Xunit.Abstractions;
using Anchor = Udap.Server.Entities.Anchor;
using Community = Udap.Server.Entities.Community;
using JsonClaimValueTypes = System.IdentityModel.Tokens.Jwt.JsonClaimValueTypes;

namespace UdapServer.Tests
{
    public class IntegrationBaseTest
    {
        public static DbContextOptions<TDbContext> BuildInMemory<TDbContext, TStoreOptions>(string name,
            TStoreOptions storeOptions)
            where TDbContext : DbContext
            where TStoreOptions : class

        {
            var serviceCollection = new ServiceCollection();
            serviceCollection.AddSingleton(storeOptions);

            var builder = new DbContextOptionsBuilder<TDbContext>();
            builder.UseInMemoryDatabase(name);
            builder.UseApplicationServiceProvider(serviceCollection.BuildServiceProvider());
            return builder.Options;
        }

        //
        //
        // public static DbContextOptions<TDbContext> BuildLocalDb<TDbContext, TStoreOptions>(string name,
        //     TStoreOptions storeOptions)
        //     where TDbContext : DbContext
        //     where TStoreOptions : class
        // {
        //     var serviceCollection = new ServiceCollection();
        //     serviceCollection.AddSingleton(storeOptions);
        //
        //     var builder = new DbContextOptionsBuilder<TDbContext>();
        //     builder.UseSqlServer(
        //         $@"Data Source=(LocalDb)\MSSQLLocalDB;database=Test.Udap.{name};trusted_connection=yes;",
        //         optionsBuilder => optionsBuilder.MigrationsAssembly(typeof(UdapDb.Program).Assembly.FullName));
        //     builder.UseApplicationServiceProvider(serviceCollection.BuildServiceProvider());
        //     return builder.Options;
        // }
    }

    public class DatabaseProviderFixture<TStoreOption> : IntegrationBaseTest, IAsyncLifetime
        where TStoreOption : class
    {
        public DbContextOptions<UdapDbContext>? DatabaseProvider;
        protected static readonly TStoreOption StoreOptions = Activator.CreateInstance<TStoreOption>();

        protected static readonly ConfigurationStoreOptions StoreOptions2 =
            Activator.CreateInstance<ConfigurationStoreOptions>();

        public string DatabaseName = "UdapTestDb";
        public X509Certificate2 AnchorCert;

        /// <summary>
        /// Called immediately after the class has been created, before it is used.
        /// </summary>
        public async Task InitializeAsync()
        {
            // File.Delete($"./Test.Udap.{DatabaseName}.db");
            using var configContext =
                new ConfigurationDbContext(
                    BuildInMemory<ConfigurationDbContext, ConfigurationStoreOptions>(DatabaseName, StoreOptions2));
            await configContext.Database.EnsureDeletedAsync();
            configContext.Database.EnsureCreated();
           // await configContext.Database.MigrateAsync();

            DatabaseProvider = BuildInMemory<UdapDbContext, TStoreOption>(DatabaseName, StoreOptions);
            using var context = new UdapDbContext(DatabaseProvider);
            // context.Database.EnsureCreated();
            if (context.Database.IsRelational())
            {
                await context.Database.MigrateAsync();
            }
            
            AnchorCert =
                new X509Certificate2(Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/anchors"),
                    "anchorLocalhostCert.cer"));

            await SeedData(context);
        }

        private async Task<int> SeedData(UdapDbContext context)
        {
            var community = new Community { Name = "http://localhost" };
            community.Enabled = true;
            community.Default = true;
            context.Communities.Add(community);
            
            context.Anchors.Add(new Anchor
            {
                BeginDate = AnchorCert.NotBefore,
                EndDate = AnchorCert.NotAfter,
                Name = AnchorCert.Subject,
                Community = community,
                X509Certificate = AnchorCert.ToPemFormat(),
                Thumbprint = AnchorCert.Thumbprint,
                Enabled = true
            });

            return await context.SaveChangesAsync();
        }

        /// <summary>
        /// Called when an object is no longer needed. Called just before <see cref="M:System.IDisposable.Dispose" />
        /// if the class also implements that.
        /// </summary>
        public Task DisposeAsync()
        {
            // if (DatabaseProvider != null)
            // {
            //     var context = (UdapDbContext)Activator.CreateInstance(typeof(UdapDbContext), DatabaseProvider)!;
            //     return context.Database.EnsureDeletedAsync();
            // }

            return Task.CompletedTask;
        }
    }

    public class IntegrationRegistrationTests : IClassFixture<DatabaseProviderFixture<UdapConfigurationStoreOptions>>
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private DbContextOptions<UdapDbContext>? _databaseProvider;
        private string _databaseName;
        private X509Certificate2 _anchorCert;

        public IntegrationRegistrationTests(DatabaseProviderFixture<UdapConfigurationStoreOptions> fixture,
            ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _databaseProvider = fixture.DatabaseProvider;
            _databaseName = fixture.DatabaseName;
            _anchorCert = fixture.AnchorCert;

        }

        [Fact]
        public async Task BadIUdapClientConfigurationStore()
        {
            var services = new ServiceCollection();
            services.AddIdentityServer()
                .AddUdapServerConfiguration();
            services.AddSingleton<IUdapClientConfigurationStore, ErrorConfigStore>();
            var sp = services.BuildServiceProvider();

            var store = sp.GetRequiredService<IUdapClientConfigurationStore>();

            var client = new Client();
            await Assert.ThrowsAsync<NotImplementedException>(async () => await store.GetClient(client));
        }


        /// <summary>
        /// Test is experimenting with multiple DBContexts.
        /// Kind of a playground for experimenting with my UDAP features in cooperation with
        /// built in IdentityServer DBContexts.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task GoodIUdapClientConfigurationStore()
        {
            var services = new ServiceCollection();
            services.AddIdentityServer()
                .AddUdapServerConfiguration();
            // services.AddSingleton(_databaseProvider);

            services.AddSingleton(new ConfigurationStoreOptions());
            
            services.AddConfigurationDbContext(options =>
            {
                options.ConfigureDbContext = b =>
                    b.UseInMemoryDatabase(_databaseName, new InMemoryDatabaseRoot());

                // options.ConfigureDbContext = b =>
                //     b.UseSqlServer($@"Data Source=(LocalDb)\MSSQLLocalDB;database=Test.Udap.{_databaseName};trusted_connection=yes;",
                //         dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));
            });

            services.AddUdapDbContext<UdapDbContext>(options =>
            {
                options.ConfigureDbContext = b =>
                    b.UseInMemoryDatabase(_databaseName, new InMemoryDatabaseRoot());
                // options.UdapDbContext = b => b.UseSqlServer($@"Data Source=(LocalDb)\MSSQLLocalDB;database=Test.Udap.{_databaseName};trusted_connection=yes;");
            });
            
            services.AddTransient<IUdapClientConfigurationStore, UdapClientConfigurationStore>();
            services.AddTransient<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
            var sp = services.BuildServiceProvider();

            var store = sp.GetRequiredService<IUdapClientConfigurationStore>();
            var adminStore = sp.GetRequiredService<IUdapClientRegistrationStore>();
            

            var client = new Client();
            client = await store.GetClient(client);
            client.Should().BeNull();


            client = new Client();
            client.ClientId = Guid.NewGuid().ToString("N");
            await adminStore.AddClient(client);
            

            client = await store.GetClient(client);
            client.Should().NotBeNull();

            //
            // Checking to see two contexts are working together.
            //
            await using (var context = sp.GetService<ConfigurationDbContext>())
            {
                client = new Client();
                var clientId = Guid.NewGuid().ToString("N");
                client.ClientId = clientId;

                var entity = await context.Clients.SingleOrDefaultAsync(c => c.ClientId == client.ClientId);
                entity.ToModel().Should().BeNull();

                context.Clients.Add(client.ToEntity());
                await context.SaveChangesAsync();
                entity = await context.Clients.SingleOrDefaultAsync(c => c.ClientId == client.ClientId);
                client = entity.ToModel();
                client.Should().NotBeNull();

                client = await store.GetClient(new Client() { ClientId = clientId });
                client.ClientId.Should().Be(clientId);

                var anchors = await store.GetAnchors();
                anchors.Count().Should().Be(1);
                anchors.First().Certificate.Should().Be(_anchorCert.ToPemFormat());
            }
        }

        [Fact]
        public async Task UdapDynamicClientRegistrationDocumentCompareToJwtPayloadTest()
        {
            var now = DateTime.UtcNow;
            var jwtId = CryptoRandom.CreateUniqueId();

            var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"), "weatherApiClientLocalhostCert.pfx");
            var clientCert = new X509Certificate2(cert, "udap-test");
            var securityKey = new X509SecurityKey(clientCert);
            var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

            var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
            var jwtHeader = new JwtHeader
            {
                { "alg", signingCredentials.Algorithm },
                { "x5c", new[] { pem } }
            };

            //
            // Could use JwtPayload.  But because we have a typed object, UdapDynamicClientRegistrationDocument
            // I have it implementing IDictionary<string,object> so the JsonExtensions.SerializeToJson method
            // can prepare it the same way JwtPayLoad is essentially implemented, but more specific to
            // this Udap Dynamic Registration.
            //
            var jwtPayload = new JwtPayload(
                new List<Claim>
                {
                    new Claim(JwtClaimTypes.Issuer, "https://weatherapi.lab:5021/fhir"),
                    new Claim(JwtClaimTypes.Subject, "https://weatherapi.lab:5021/fhir"),
                    new Claim(JwtClaimTypes.Audience, "https://weatherapi.lab:5021/connect/register"),
                    new Claim(JwtClaimTypes.Expiration,
                        EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                    new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                        ClaimValueTypes.Integer),
                    new Claim(JwtClaimTypes.JwtId, jwtId),
                    new Claim("client_name", "udapTestClient"),
                    new Claim("contacts", JsonSerializer.Serialize(new HashSet<string> { "FhirJoe@BridgeTown.lab" }),
                        JsonClaimValueTypes.JsonArray),
                    new Claim("grant_types",
                        JsonSerializer.Serialize(new HashSet<string> { "client_credentials", "joe" }),
                        JsonClaimValueTypes.JsonArray),
                    new Claim("response_types", JsonSerializer.Serialize(new HashSet<string> { "authorization_code" }),
                        JsonClaimValueTypes.JsonArray),
                    new Claim("token_endpoint_auth_method", "private_key_jwt"),
                    new Claim(JwtClaimTypes.Scope, "system/Patient.* system/Practitioner.read")
                });

            var document = new UdapDynamicClientRegistrationDocument
            {
                Issuer = "https://weatherapi.lab:5021/fhir",
                Subject = "https://weatherapi.lab:5021/fhir",
                Audience = "https://weatherapi.lab:5021/connect/register",
                Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
                IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
                JwtId = jwtId,
                ClientName = "udapTestClient",
                Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab" },
                GrantTypes = new HashSet<string> { "client_credentials", "joe" },
                ResponseTypes = new HashSet<string> { "authorization_code" },
                TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
                Scope = "system/Patient.* system/Practitioner.read"
            };
            // _testOutputHelper.WriteLine(JsonSerializer.Serialize(jwtPayload, new JsonSerializerOptions { WriteIndented = true }));

            var encodedHeader = jwtHeader.Base64UrlEncode();
            var encodedPayloadJwt = jwtPayload.Base64UrlEncode();
            var encodedPayload = document.Base64UrlEncode();
            var encodedSignature =
                JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                    signingCredentials);
            var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayloadJwt, ".", encodedSignature);

            JsonExtensions.SerializeToJson(jwtPayload).Should()
                .BeEquivalentTo(JsonExtensions.SerializeToJson(document));

            encodedPayloadJwt.Should().BeEquivalentTo(encodedPayload);

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadToken(signedSoftwareStatement) as JwtSecurityToken;
            foreach (var tokenClaim in token.Claims)
            {
                _testOutputHelper.WriteLine(tokenClaim.Value);
            }
        }


        [Fact]
        public async Task GoodIUdapClientRegistrationStore()
        {
            var services = new ServiceCollection();


            //
            // Certificate revocation is offline for unit tests.
            //
            var problemFlags = X509ChainStatusFlags.NotTimeValid |
                               X509ChainStatusFlags.Revoked |
                               X509ChainStatusFlags.NotSignatureValid |
                               X509ChainStatusFlags.InvalidBasicConstraints |
                               X509ChainStatusFlags.CtlNotTimeValid |
                               // X509ChainStatusFlags.OfflineRevocation |
                               X509ChainStatusFlags.CtlNotSignatureValid;

            services.AddSingleton(new TrustChainValidator(new X509ChainPolicy(), problemFlags,
                _testOutputHelper.ToLogger<TrustChainValidator>()));


            services.AddIdentityServer()
                .AddUdapServerConfiguration();

            services.AddUdapDbContext<UdapDbContext>(options =>
            {
                options.ConfigureDbContext = b =>
                    b.UseInMemoryDatabase(_databaseName, new InMemoryDatabaseRoot());
                // options.UdapDbContext = b =>
                //     b.UseSqlServer($@"Data Source=(LocalDb)\MSSQLLocalDB;database=Test.Udap.{_databaseName};trusted_connection=yes;", o =>
                //         o.MigrationsAssembly(typeof(UdapDiscoveryEndpoint).Assembly.FullName));
            });

            services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
            services.AddScoped<UdapDynamicClientRegistrationEndpoint, UdapDynamicClientRegistrationEndpoint>();

            var sp = services.BuildServiceProvider();

            var validator = sp.GetRequiredService<IUdapDynamicClientRegistrationValidator>();

            
            var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "WeatherApiClientLocalhostCert.pfx"); 
            var clientCert = new X509Certificate2(cert, "udap-test");
            var securityKey = new X509SecurityKey(clientCert);
            var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

            var now = DateTime.UtcNow;

            var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
            var jwtHeader = new JwtHeader
            {
                { "alg", signingCredentials.Algorithm },
                { "x5c", new[] { pem } }
            };

            var jwtId = CryptoRandom.CreateUniqueId();
            //
            // Could use JwtPayload.  But because we have a typed object, UdapDynamicClientRegistrationDocument
            // I have it implementing IDictionary<string,object> so the JsonExtensions.SerializeToJson method
            // can prepare it the same way JwtPayLoad is essentially implemented, but more light weight
            // and specific to this Udap Dynamic Registration.
            //

            var document = new UdapDynamicClientRegistrationDocument
            {
                Issuer = "https://weatherapi.lab:5021/fhir",
                Subject = "https://weatherapi.lab:5021/fhir",
                Audience = "https://weatherapi.lab:5021/connect/register",
                Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
                IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
                JwtId = jwtId,
                ClientName = "udapTestClient",
                Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
                GrantTypes = new HashSet<string> { "client_credentials" },
                ResponseTypes = new HashSet<string> { "authorization_code" },
                TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
                Scope = "system/Patient.* system/Practitioner.read"
            };


            var encodedHeader = jwtHeader.Base64UrlEncode();
            var encodedPayload = document.Base64UrlEncode();
            var encodedSignature =
                JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                    signingCredentials);
            var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
            // _testOutputHelper.WriteLine(signedSoftwareStatement);

            var requestBody = new UdapRegisterRequest
            {
                SoftwareStatement = signedSoftwareStatement,
                Udap = UdapConstants.UdapVersionsSupportedValue
            };

            document.ClientId.Should().BeNull();

            var store = sp.GetRequiredService<IUdapClientRegistrationStore>();
            var communityAnchors = await store.GetAnchorsCertificates("http://localhost");
            // TODO Store still needs a trusted roots place to store data
            // var trustedRoots = await store.GetRootCertificates("http://localhost");
            var trustedRoots = new X509Certificate2Collection();
            trustedRoots.Add(new X509Certificate2(
                Path.Combine(AppContext.BaseDirectory, "CertStore/roots", "caLocalhostCert.cer")
            ));
            
            var result = await validator.ValidateAsync(requestBody, communityAnchors, trustedRoots);

            result.IsError.Should().BeFalse($"{result.Error} : {result.ErrorDescription}");
            result.Document.Should().BeEquivalentTo(document);
        }

        /// <summary>
        /// Issuer of the JWT -- unique identifying client URI. This SHALL match the value of a
        /// uniformResourceIdentifier entry in the Subject Alternative Name extension of the client's
        /// certificate included in the x5c JWT header
        ///
        /// The unique client URI used for the iss claim SHALL match the uriName entry in the Subject Alternative Name
        /// extension of the client app operator’s X.509 certificate, and SHALL uniquely identify a single client app
        /// operator and application over time. 
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task iss_and_sub_and_aud_Tests()
        {
            Assert.Fail("Not Implemented");
        }

        /// <summary>
        /// Expiration time integer for this software statement, expressed in seconds since the "Epoch"
        /// (1970-01-01T00:00:00Z UTC). The exp time SHALL be no more than 5 minutes after the value of the iat claim.
        ///
        /// The software statement is intended for one-time use with a single OAuth 2.0 server. As such, the aud
        /// claim SHALL list the URL of the OAuth Server’s registration endpoint, and the lifetime of the software
        /// statement (exp minus iat) SHALL be 5 minutes.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task exp_and_iat_Test()
        {
            Assert.Fail("Not Implemented");
        }

        /// <summary>
        /// An array of one or more redirection URIs used by the client application.
        /// This claim SHALL be present if grant_types includes "authorization_code" and this claim
        /// SHALL be absent otherwise. Each URI SHALL use the https scheme.
        /// </summary>
        /// <returns></returns>
        // TODO still need to work on this test. Only spent enough time here to determine
        // I was not including redirect Uris in when deserializing claims
        [Fact]
        public async Task redirect_uris_Tests() //With and without authorization_code in grant_types
        {
            var now = DateTime.UtcNow;
            var jwtId = CryptoRandom.CreateUniqueId();

            var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"), "weatherApiClientLocalhostCert.pfx");
            var clientCert = new X509Certificate2(cert, "udap-test");
            var securityKey = new X509SecurityKey(clientCert);
            var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

            var pem = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
            var jwtHeader = new JwtHeader
            {
                { "alg", signingCredentials.Algorithm },
                { "x5c", new[] { pem } }
            };

            var testRedirectUri = $"https://fhirlabs.net/udapTestClient/redirect/{Guid.NewGuid()}";

            //
            // Could use JwtPayload.  But because we have a typed object, UdapDynamicClientRegistrationDocument
            // I have it implementing IDictionary<string,object> so the JsonExtensions.SerializeToJson method
            // can prepare it the same way JwtPayLoad is essentially implemented, but more specific to
            // this Udap Dynamic Registration.
            //
            var jwtPayload = new JwtPayload(
                new List<Claim>
                {
                    new Claim(JwtClaimTypes.Issuer, "https://weatherapi.lab:5021/fhir"),
                    new Claim(JwtClaimTypes.Subject, "https://weatherapi.lab:5021/fhir"),
                    new Claim(JwtClaimTypes.Audience, "https://weatherapi.lab:5021/connect/register"),
                    new Claim(JwtClaimTypes.Expiration,
                        EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                    new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                        ClaimValueTypes.Integer),
                    new Claim(JwtClaimTypes.JwtId, jwtId),
                    new Claim("client_name", "udapTestClient"),
                    new Claim("contacts", JsonSerializer.Serialize(new HashSet<string> { "FhirJoe@BridgeTown.lab" }),
                        JsonClaimValueTypes.JsonArray),
                    new Claim("redirect_uris", JsonSerializer.Serialize(new HashSet<string> { testRedirectUri } ),
                        JsonClaimValueTypes.JsonArray),
                    new Claim("grant_types",
                        JsonSerializer.Serialize(new HashSet<string> { "authorization_code" }),
                        JsonClaimValueTypes.JsonArray),
                    new Claim("response_types", JsonSerializer.Serialize(new HashSet<string> { "code" }),
                        JsonClaimValueTypes.JsonArray),
                    new Claim("token_endpoint_auth_method", "private_key_jwt"),
                    new Claim(JwtClaimTypes.Scope, "system/Patient.* system/Practitioner.read")
                });

            var document = new UdapDynamicClientRegistrationDocument
            {
                Issuer = "https://weatherapi.lab:5021/fhir",
                Subject = "https://weatherapi.lab:5021/fhir",
                Audience = "https://weatherapi.lab:5021/connect/register",
                Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
                IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
                JwtId = jwtId,
                ClientName = "udapTestClient",
                Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab" },
                RedirectUris = new List<string>{new Uri(testRedirectUri).AbsoluteUri },
                GrantTypes = new HashSet<string> { "authorization_code" },
                ResponseTypes = new HashSet<string> { "code" },
                TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
                Scope = "system/Patient.* system/Practitioner.read"
            };
            // _testOutputHelper.WriteLine(JsonSerializer.Serialize(jwtPayload, new JsonSerializerOptions { WriteIndented = true }));

            var encodedHeader = jwtHeader.Base64UrlEncode();
            var encodedPayloadJwt = jwtPayload.Base64UrlEncode();
            var encodedPayload = document.Base64UrlEncode();
            var encodedSignature =
                JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                    signingCredentials);
            var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayloadJwt, ".", encodedSignature);

            JsonExtensions.SerializeToJson(jwtPayload).Should()
                .BeEquivalentTo(JsonExtensions.SerializeToJson(document));
            
            encodedPayloadJwt.Should().BeEquivalentTo(encodedPayload);
            
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadToken(signedSoftwareStatement) as JwtSecurityToken;
            foreach (var tokenClaim in token.Claims)
            {
                _testOutputHelper.WriteLine(tokenClaim.Value);
            }
        }

        /// <summary>
        /// An array of URI strings indicating how the data holder can contact the app operator regarding the application.
        /// The array SHALL contain at least one valid email address using the mailto scheme, e.g.
        /// ["mailto:operations@example.com"]
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task contacts_Test()
        {
            Assert.Fail("Not Implemented");
        }

        /// <summary>
        /// A URL string referencing an image associated with the client application, i.e. a logo.
        /// If grant_types includes "authorization_code", client applications SHALL include this field,
        /// and the Authorization Server MAY display this logo to the user during the authorization process.
        /// The URL SHALL use the https scheme and reference a PNG, JPG, or GIF image file,
        /// e.g. "https://myapp.example.com/MyApp.png"
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task logo_uri_Tests()
        {
            Assert.Fail("Not Implemented");
        }

        /// <summary>
        /// Array of strings, each representing a requested grant type, from the following list:
        /// "authorization_code", "refresh_token", "client_credentials".
        /// The array SHALL include either "authorization_code" or "client_credentials", but not both. '
        /// The value "refresh_token" SHALL NOT be present in the array unless "authorization_code" is also present.
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task grant_types_Tests()
        {
            Assert.Fail("Not Implemented");
        }

        /// <summary>
        /// Array of strings. If grant_types contains "authorization_code", then this element SHALL
        /// have a fixed value of ["code"], and SHALL be omitted otherwise
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task response_types_Tests()
        {
            Assert.Fail("Not Implemented");
        }

        [Fact]
        public async Task SignedCertifications_Tests()
        {
            Assert.Fail("Not Implemented");
        }

        internal class ErrorConfigStore : IUdapClientConfigurationStore
        {
            public Task<Client?> GetClient(Client client, CancellationToken token = default)
            {
                throw new NotImplementedException();
            }

            public Task<IEnumerable<Udap.Common.Models.Anchor>> GetAnchors(CancellationToken token = default)
            {
                throw new NotImplementedException();
            }
        }
    }
}