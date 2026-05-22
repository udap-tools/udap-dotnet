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
using System.Text.Json;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Options;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Duende.IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Common.Certificates;
using Udap.Auth.Server;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Server.Configuration.DependencyInjection;
using Udap.Server.Registration;
using Udap.Server.Storage.DbContexts;
using Udap.Server.Storage.Stores;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using JsonClaimValueTypes = System.IdentityModel.Tokens.Jwt.JsonClaimValueTypes;
#pragma warning disable xUnit1004

namespace UdapServer.Tests
{
    public class DatabaseProviderFixture : IAsyncLifetime
    {
        public readonly string DatabaseName = "UdapTestDb";
#if NET9_0_OR_GREATER
        public required X509Certificate2 AnchorCert = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/anchors"),
            "caWeatherApiLocalhostCert.cer"));
#else
        public required X509Certificate2 AnchorCert = new X509Certificate2(Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/anchors"),
            "caWeatherApiLocalhostCert.cer"));
#endif

        /// <summary>
        /// Called immediately after the class has been created, before it is used.
        /// </summary>
        public Task InitializeAsync()
        {
            return SeedData.EnsureSeedData($@"Data Source=./Udap.Idp.db.{DatabaseName};", Substitute.For<Serilog.ILogger>());

            // await SeedData();
        }

        
        /// <summary>
        /// Called when an object is no longer needed. Called just before <see cref="M:System.IDisposable.Dispose" />
        /// if the class also implements that.
        /// </summary>
        public Task DisposeAsync()
        {
            return Task.CompletedTask;
        }
    }

    [Collection("Udap.Auth.Server")]
    public class IntegrationRegistrationTests : IClassFixture<DatabaseProviderFixture>
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly string _databaseName;
        private readonly X509Certificate2 _anchorCert;

        public IntegrationRegistrationTests(DatabaseProviderFixture fixture,
            ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _databaseName = fixture.DatabaseName;
            _anchorCert = fixture.AnchorCert;

        }
        

        [Fact]
        public async Task BadIUdapClientConfigurationStore()
        {
            var services = new ServiceCollection();
            
            var builder = services.AddUdapServerBuilder();
            builder.AddUdapServerConfiguration();

            services.AddIdentityServer();
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

            var builder = services.AddUdapServerBuilder();
            builder.AddUdapServerConfiguration();

            services.AddIdentityServer();
            // services.AddSingleton(_databaseProvider);

            services.AddSingleton(new ConfigurationStoreOptions());
            
            services.AddConfigurationDbContext(options =>
            {
                // options.ConfigureDbContext = b =>
                //     b.UseInMemoryDatabase(_databaseName, new InMemoryDatabaseRoot());

                options.ConfigureDbContext = b =>
                    b.UseSqlite($@"Data Source=Udap.Idp.db.{_databaseName};",
                        dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));
            });

            services.AddUdapDbContext<UdapDbContext>(options =>
            {
                // options.ConfigureDbContext = b =>
                //     b.UseInMemoryDatabase(_databaseName, new InMemoryDatabaseRoot());
                options.UdapDbContext = b =>
                    b.UseSqlite($@"Data Source=Udap.Idp.db.{_databaseName};");
            });
            
            services.AddTransient<IUdapClientConfigurationStore, UdapClientConfigurationStore>();
            services.AddTransient<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
            var sp = services.BuildServiceProvider();

            var store = sp.GetRequiredService<IUdapClientConfigurationStore>();
            var adminStore = sp.GetRequiredService<IUdapClientRegistrationStore>();
            

            var client = new Client();
            client = await store.GetClient(client);
            Assert.Null(client);


            client = new Client
            {
                ClientId = Guid.NewGuid().ToString("N")
            };
            await adminStore.UpsertClient(client);
            

            client = await store.GetClient(client);
            Assert.NotNull(client);

            //
            // Checking to see two contexts are working together.
            //
            await using var context = sp.GetRequiredService<ConfigurationDbContext>();
            client = new Client();
            var clientId = Guid.NewGuid().ToString("N");
            client.ClientId = clientId;

            var entity = await context.Clients.SingleOrDefaultAsync(c => c.ClientId == client.ClientId);
            Assert.Null(entity);

            context.Clients.Add(client.ToEntity());
            await context.SaveChangesAsync();
            entity = await context.Clients.SingleOrDefaultAsync(c => c.ClientId == client.ClientId);
            client = entity.ToModel();
            Assert.NotNull(client);

            client = await store.GetClient(new Client() { ClientId = clientId });
            Assert.Equal(clientId, client!.ClientId);

            var anchors = (await store.GetAnchors()).ToList();
            Assert.Equal(2, anchors.Count);
            Assert.Equal(_anchorCert.ToPemFormat().ToLf(), anchors.First().Certificate.ToLf(), StringComparer.OrdinalIgnoreCase);
        }


        [Fact]
        public void UdapDynamicClientRegistrationDocumentCompareToJwtPayloadTest()
        {
            var now = DateTime.UtcNow;
            var jwtId = CryptoRandom.CreateUniqueId();

            var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"), "weatherApiClientLocalhostCert1.pfx");
#if NET9_0_OR_GREATER
            var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
            var clientCert = new X509Certificate2(cert, "udap-test");
#endif
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
                    new (JwtClaimTypes.Issuer, "https://weatherapi.lab:5021/fhir"),
                    new (JwtClaimTypes.Subject, "https://weatherapi.lab:5021/fhir"),
                    new (JwtClaimTypes.Audience, "https://weatherapi.lab:5021/connect/register"),
                    new (JwtClaimTypes.Expiration,
                        EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                    new (JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                        ClaimValueTypes.Integer),
                    new (JwtClaimTypes.JwtId, jwtId),
                    new ("client_name", "udapTestClient"),
                    new ("contacts", JsonSerializer.Serialize(new HashSet<string> { "FhirJoe@BridgeTown.lab" }),
                        JsonClaimValueTypes.JsonArray),
                    new ("grant_types",
                        JsonSerializer.Serialize(new HashSet<string> { "client_credentials", "joe" }),
                        JsonClaimValueTypes.JsonArray),
                    new ("response_types", JsonSerializer.Serialize(new HashSet<string> { "authorization_code" }),
                        JsonClaimValueTypes.JsonArray),
                    new ("token_endpoint_auth_method", "private_key_jwt"),
                    new (JwtClaimTypes.Scope, "system/Patient.* system/Practitioner.read")
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

            Assert.Equal(JsonSerializer.Serialize(document), jwtPayload.SerializeToJson(), StringComparer.OrdinalIgnoreCase);

            Assert.Equal(encodedPayload, encodedPayloadJwt, StringComparer.OrdinalIgnoreCase);

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadToken(signedSoftwareStatement) as JwtSecurityToken;
            foreach (var tokenClaim in token!.Claims)
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
            var problemFlags = ChainProblemStatus.NotTimeValid |
                               ChainProblemStatus.Revoked |
                               ChainProblemStatus.NotSignatureValid |
                               ChainProblemStatus.InvalidBasicConstraints;

            services.AddSingleton(new TrustChainValidator(
                problemFlags,
                false,
                _testOutputHelper.ToLogger<TrustChainValidator>()));


            var builder = services.AddUdapServerBuilder();
            builder.AddUdapServerConfiguration()
                .AddUdapInMemoryApiScopes(new List<ApiScope>(){new ApiScope("system/Practitioner.read")});

            services.AddIdentityServer();
                

            services.AddUdapDbContext<UdapDbContext>(options =>
            {
                // options.ConfigureDbContext = b =>
                //     b.UseInMemoryDatabase(_databaseName, new InMemoryDatabaseRoot());
                options.UdapDbContext = b =>
                    b.UseSqlite($@"Data Source=Udap.Idp.db.{_databaseName};", 
                        o => o.MigrationsAssembly(typeof(Program).Assembly.FullName));
            });

            services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
            services.AddScoped<UdapDynamicClientRegistrationEndpoint, UdapDynamicClientRegistrationEndpoint>();
            services.AddSingleton(new ServerSettings { SsraaVersion = SsraaVersion.V1_1 });
            
            var mockHttpContextAccessor = Substitute.For<IHttpContextAccessor>();
            var context = new DefaultHttpContext();
            context.Request.Scheme = "http";
            context.Request.Host = new HostString("localhost:5001");
            context.Request.Path = "/connect/register";
            mockHttpContextAccessor.HttpContext.Returns(context);
            
            services.AddSingleton(mockHttpContextAccessor);


            // services.AddSingleton<IHttpContextAccessor>(new HttpContextAccessor(){new DefaultHttpContext(){ Request = { Path = "/"}}});

            var sp = services.BuildServiceProvider();

            var validator = sp.GetRequiredService<IUdapDynamicClientRegistrationValidator>();


            var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "weatherApiClientLocalhostCert1.pfx");
#if NET9_0_OR_GREATER
            var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
            var clientCert = new X509Certificate2(cert, "udap-test");
#endif
            var now = DateTime.UtcNow;
            var jwtId = CryptoRandom.CreateUniqueId();

            var document = new UdapDynamicClientRegistrationDocument
            {
                Issuer = "http://localhost/",
                Subject = "http://localhost/",
                Audience = "http://localhost:5001/connect/register",
                Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
                IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
                JwtId = jwtId,
                ClientName = "udapTestClient",
                Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
                GrantTypes = new HashSet<string> { "client_credentials" },
                ResponseTypes = new HashSet<string> { "authorization_code" },
                TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
                Scope = "system/Practitioner.read"
            };


            var signedSoftwareStatement =
                SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                    .Create(clientCert, document)
                    .Build();

            var requestBody = new UdapRegisterRequest
            (
                signedSoftwareStatement,
                 UdapConstants.UdapVersionsSupportedValue
            );

            Assert.Null(document.ClientId);

            var store = sp.GetRequiredService<IUdapClientRegistrationStore>();
            var communityAnchors = await store.GetAnchorsCertificates("http://localhost");
            var anchors = (await store.GetAnchors("http://localhost")).ToArray();
            var intermediateCerts = new X509Certificate2Collection(anchors.First().Intermediates!
                .Select(s => X509Certificate2.CreateFromPem(s.Certificate)).ToArray());

            var registrationContext = new UdapDynamicClientRegistrationContext { Request = requestBody };
            var result = await validator.ValidateAsync(
                registrationContext,
                intermediateCerts,
                communityAnchors!,
                anchors);

            Assert.False(result.IsError, $"{result.Error} : {result.ErrorDescription}");
            Assert.Equal(document, result.Document);


        }

        [Fact]
        public async Task GoodCertificationsRegistrationStore()
        {
            var services = new ServiceCollection();

            //
            // Certificate revocation is offline for unit tests.
            //
            var problemFlags = ChainProblemStatus.NotTimeValid |
                               ChainProblemStatus.Revoked |
                               ChainProblemStatus.NotSignatureValid |
                               ChainProblemStatus.InvalidBasicConstraints;

            services.AddSingleton(new TrustChainValidator(
                problemFlags,
                false,
                _testOutputHelper.ToLogger<TrustChainValidator>()));


            var builder = services.AddUdapServerBuilder();
            builder.AddUdapServerConfiguration()
                .AddUdapInMemoryApiScopes(new List<ApiScope>() { new ApiScope("system/Practitioner.read") });

            services.AddIdentityServer();


            services.AddUdapDbContext<UdapDbContext>(options =>
            {
                // options.ConfigureDbContext = b =>
                //     b.UseInMemoryDatabase(_databaseName, new InMemoryDatabaseRoot());
                options.UdapDbContext = b =>
                    b.UseSqlite($@"Data Source=Udap.Idp.db.{_databaseName};",
                        o => o.MigrationsAssembly(typeof(Program).Assembly.FullName));
            });

            services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
            services.AddScoped<UdapDynamicClientRegistrationEndpoint, UdapDynamicClientRegistrationEndpoint>();
            services.AddSingleton(new ServerSettings { SsraaVersion = SsraaVersion.V1_1 });

            var mockHttpContextAccessor = Substitute.For<IHttpContextAccessor>();
            var context = new DefaultHttpContext();
            context.Request.Scheme = "http";
            context.Request.Host = new HostString("localhost:5001");
            context.Request.Path = "/connect/register";
            mockHttpContextAccessor.HttpContext.Returns(context);

            services.AddSingleton(mockHttpContextAccessor);


            // services.AddSingleton<IHttpContextAccessor>(new HttpContextAccessor(){new DefaultHttpContext(){ Request = { Path = "/"}}});

            var sp = services.BuildServiceProvider();

            var validator = sp.GetRequiredService<IUdapDynamicClientRegistrationValidator>();


            var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "weatherApiClientLocalhostCert1.pfx");
#if NET9_0_OR_GREATER
            var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
            var clientCert = new X509Certificate2(cert, "udap-test");
#endif
            var now = DateTime.UtcNow;
            var jwtId = CryptoRandom.CreateUniqueId();

            var document = new UdapDynamicClientRegistrationDocument
            {
                Issuer = "http://localhost/",
                Subject = "http://localhost/",
                Audience = "http://localhost:5001/connect/register",
                Expiration = EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()),
                IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
                JwtId = jwtId,
                ClientName = "udapTestClient",
                Contacts = new HashSet<string> { "FhirJoe@BridgeTown.lab", "FhirJoe@test.lab" },
                GrantTypes = new HashSet<string> { "client_credentials" },
                ResponseTypes = new HashSet<string> { "authorization_code" },
                TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
                Scope = "system/Practitioner.read"
            };

            var signedSoftwareStatement =
                SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                    .Create(clientCert, document)
                    .Build();

            // var certifications = new UdapCertificationAndEndorsementDocument("TestCertification");
            // certifications



            var requestBody = new UdapRegisterRequest
            (
                signedSoftwareStatement,
                 UdapConstants.UdapVersionsSupportedValue
            );

            Assert.Null(document.ClientId);

            var store = sp.GetRequiredService<IUdapClientRegistrationStore>();
            var communityAnchors = await store.GetAnchorsCertificates("http://localhost");
            var anchors = (await store.GetAnchors("http://localhost")).ToArray();
            var intermediateCerts = new X509Certificate2Collection(anchors.First().Intermediates!
                .Select(s => X509Certificate2.CreateFromPem(s.Certificate)).ToArray());

            var registrationContext = new UdapDynamicClientRegistrationContext { Request = requestBody };
            var result = await validator.ValidateAsync(
                registrationContext,
                intermediateCerts,
                communityAnchors!,
                anchors);

            Assert.False(result.IsError, $"{result.Error} : {result.ErrorDescription}");
            Assert.Equal(document, result.Document);


        }
        /// <summary>
        /// Issuer of the JWT -- unique identifying client URI. This SHALL match the value of a
        /// uniformResourceIdentifier entry in the Subject Alternative Name extension of the client's
        /// certificate included in the x5c JWT header
        ///
        /// The unique client URI used for the iss claim SHALL match the uriName entry in the Subject Alternative Name
        /// extension of the client app operator�s X.509 certificate, and SHALL uniquely identify a single client app
        /// operator and application over time. 
        /// </summary>
        /// <returns></returns>
        [Fact(Skip = "xxx")]
        public void iss_and_sub_and_aud_Tests()
        {
            Assert.Fail("Not Implemented");
        }

        /// <summary>
        /// Expiration time integer for this software statement, expressed in seconds since the "Epoch"
        /// (1970-01-01T00:00:00Z UTC). The exp time SHALL be no more than 5 minutes after the value of the iat claim.
        ///
        /// The software statement is intended for one-time use with a single OAuth 2.0 server. As such, the aud
        /// claim SHALL list the URL of the OAuth Server�s registration endpoint, and the lifetime of the software
        /// statement (exp minus iat) SHALL be 5 minutes.
        /// </summary>
        /// <returns></returns>
        [Fact(Skip = "xxx")]
        public void exp_and_iat_Test()
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
        public void redirect_uris_Tests() //With and without authorization_code in grant_types
        {
            var now = DateTime.UtcNow;
            var jwtId = CryptoRandom.CreateUniqueId();

            var cert = Path.Combine(Path.Combine(AppContext.BaseDirectory, "CertStore/issued"), "weatherApiClientLocalhostCert1.pfx");
#if NET9_0_OR_GREATER
            var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
            var clientCert = new X509Certificate2(cert, "udap-test");
#endif
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
                    new (JwtClaimTypes.Issuer, "https://weatherapi.lab:5021/fhir"),
                    new (JwtClaimTypes.Subject, "https://weatherapi.lab:5021/fhir"),
                    new (JwtClaimTypes.Audience, "https://weatherapi.lab:5021/connect/register"),
                    new (JwtClaimTypes.Expiration,
                        EpochTime.GetIntDate(now.AddMinutes(1).ToUniversalTime()).ToString(), ClaimValueTypes.Integer),
                    new (JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                        ClaimValueTypes.Integer),
                    new (JwtClaimTypes.JwtId, jwtId),
                    new ("client_name", "udapTestClient"),
                    new ("contacts", JsonSerializer.Serialize(new HashSet<string> { "FhirJoe@BridgeTown.lab" }),
                        JsonClaimValueTypes.JsonArray),
                    new ("redirect_uris", JsonSerializer.Serialize(new HashSet<string> { testRedirectUri } ),
                        JsonClaimValueTypes.JsonArray),
                    new ("grant_types",
                        JsonSerializer.Serialize(new HashSet<string> { "authorization_code" }),
                        JsonClaimValueTypes.JsonArray),
                    new ("response_types", JsonSerializer.Serialize(new HashSet<string> { "code" }),
                        JsonClaimValueTypes.JsonArray),
                    new ("token_endpoint_auth_method", "private_key_jwt"),
                    new (JwtClaimTypes.Scope, "system/Patient.* system/Practitioner.read")
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

            Assert.Equal(JsonSerializer.Serialize(document), jwtPayload.SerializeToJson(), StringComparer.OrdinalIgnoreCase);
            
            Assert.Equal(encodedPayload, encodedPayloadJwt, StringComparer.OrdinalIgnoreCase);
            
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadToken(signedSoftwareStatement) as JwtSecurityToken;

            foreach (var tokenClaim in token!.Claims)
            {
                _testOutputHelper.WriteLine(tokenClaim.Value);
            }
        }


        [Fact]
        public void TestSerialization()
        {
            var cert = Path.Combine(AppContext.BaseDirectory, "CertStore/issued", "fhirlabs.net.client.pfx");
#if NET9_0_OR_GREATER
            var clientCert = X509CertificateLoader.LoadPkcs12FromFile(cert, "udap-test");
#else
            var clientCert = new X509Certificate2(cert, "udap-test");
#endif

            var document = UdapDcrBuilderForAuthorizationCode
                .Create(clientCert)
                .WithAudience("https://securedcontrols.net/connect/register")
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName("dotnet system test client")
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithScope("user/Patient.* user/Practitioner.read") //Comment out for UDAP Server mode.
                .WithResponseTypes(new HashSet<string> { "code" })
                .WithRedirectUrls(new List<string> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri })
                .Build();

            var documentSerialized = document.SerializeToJson();
            
            _testOutputHelper.WriteLine(documentSerialized);

            // var docDeserialized =
            //     JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(documentSerialized);

            // var docDeserialized = JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(documentSerialized);
            //_testOutputHelper.WriteLine(docDeserialized.RedirectUris.First());


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
