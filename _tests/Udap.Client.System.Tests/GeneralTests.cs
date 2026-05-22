#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Udap.Client;
using Udap.Client.Extensions;
using Udap.Client.Messages;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using DiscoveryPolicy = Udap.Client.DiscoveryPolicy;

namespace Udap.Client.System.Tests
{
    public class GeneralTests
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly FakeChainValidatorDiagnostics _diagnosticsChainValidator = new FakeChainValidatorDiagnostics();

        public GeneralTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public async Task Test1()
        {
            var client = new HttpClient();
            var response = await client.GetAsync("https://test.udap.org/fhir/r4/stage/metadata");
            var metadata = await response.Content.ReadAsStringAsync();
            Assert.False(string.IsNullOrEmpty(metadata));
            // _testOutputHelper.WriteLine(metadata);
            //
            // Example
            //

            #region example metadata for security.extensions

            /*
            {
                "resourceType": "CapabilityStatement",
                "version": "1636389333424",
                "status": "active",
                "date": "2021-11-08T08:35:33-08:00",
                "kind": "instance",
                "instantiates": [
                "http://hl7.org/fhir/us/core/CapabilityStatement/us-core-server|3.1.1",
                "http://hl7.org/fhir/uv/bulkdata/CapabilityStatement/bulk-data|1.0.0"
                    ],
                "implementation": {
                    "description": "PROD"
                },
                "fhirVersion": "4.0.1",
                "format": [
                "application/fhir+xml",
                "application/fhir+json"
                    ],
                "rest": [
                {
                    "mode": "server",
                    "security": {
                        "extension": [
                        {
                            "url": "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris",
                            "extension": [
                            {
                                "url": "token",
                                "valueUri": "https://test.udap.org/oauth/stage/token"
                            },
                            {
                                "url": "authorize",
                                "valueUri": "https://test.udap.org/oauth/stage/authz"
                            },
                            {
                                "url": "register",
                                "valueUri": "https://test.udap.org/oauth/stage/register"
                            }
                            ]
                        }
                        ],
                        "service": [
                        {
                            "coding": [
                            {
                                "system": "http://hl7.org/fhir/restful-security-service",
                                "code": "SMART-on-FHIR"
                            }
                            ],
                            "text": "OAuth2 using SMART-on-FHIR profile (see http://docs.smarthealthit.org)"
                        },
                        {
                            "coding": [
                            {
                                "system": "http://fhir.udap.org/CodeSystem/capability-rest-security-service",
                                "code": "UDAP"
                            }
                            ],
                            "text": "OAuth 2 using UDAP profile (see http://www.udap.org)"
                        }
                        ]
                    }
                }
            }
            */

            #endregion
        }

        [Fact]
        public async Task UdapClientDiscoveryForIdentityProvider()
        {
            var client = new HttpClient();
            var disco = await client.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
            {
                Address = "https://securedcontrols.net:5001",
                Policy = new DiscoveryPolicy()
                {
                    DiscoveryDocumentPath = ".well-known/udap"
                }
            });
            if (disco.IsError)
            {
                _testOutputHelper.WriteLine(disco.Error);
            }
            _testOutputHelper.WriteLine(disco.Json.ToString());
            var discoJsonFormatted = JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
            _testOutputHelper.WriteLine(discoJsonFormatted);
        }

        [Fact]
        public async Task RegistrationEndpointExpected()
        {
            var client = new HttpClient();
            var disco = await client.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
            {
                Address = "https://securedcontrols.net",
                Policy = new DiscoveryPolicy()
                {
                    DiscoveryDocumentPath = ".well-known/udap"
                }
            });
            if (disco.IsError)
            {
                _testOutputHelper.WriteLine(disco.Error);
            }

            var registrationEndpoint = disco.RegistrationEndpoint;
            Assert.Equal("https://securedcontrols.net/connect/register", registrationEndpoint, StringComparer.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task UdapClientDiscoveryForFhirServer()
        {
            var client = new HttpClient();
            var disco = await client.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
            {
                Address = "https://fhirlabs.net/fhir/r4", 
                Community = "udap://fhirlabs.net/",
                Policy = new DiscoveryPolicy { 
                    ValidateEndpoints = false   // Authority endpoints are not hosted on same domain as Identity Provider.
                }
            });

            //_testOutputHelper.WriteLine(disco.Json.ToString());
            // var discoJsonFormatted = JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
            //_testOutputHelper.WriteLine(discoJsonFormatted);

            var metadata = disco.Json?.Deserialize<UdapMetadata>();
            var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
            var tokenHeader = jwt.Header;
            // _testOutputHelper.WriteLine(tokenHeader.X5c);
            var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray()!;

#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5CArray.First()!.ToString()));
#else
            var cert = new X509Certificate2(Convert.FromBase64String(x5CArray.First()!.ToString()));
#endif
            var tokenHandler = new JwtSecurityTokenHandler();

            tokenHandler.ValidateToken(metadata.SignedMetadata, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = ["https://fhirlabs.net/fhir/r4"], //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                ValidateAudience = false, // No aud for UDAP metadata
                ValidateLifetime = true,
                IssuerSigningKey = new X509SecurityKey(cert),
                ValidAlgorithms = [tokenHeader.Alg], //must match signing algorithm

            }, out _);

            var problemFlags = ChainProblemStatus.NotTimeValid |
                               ChainProblemStatus.Revoked |
                               ChainProblemStatus.NotSignatureValid |
                               ChainProblemStatus.InvalidBasicConstraints |
                               ChainProblemStatus.OfflineRevocation;

            Assert.True(await ValidateCertificateChain(cert, problemFlags, "udap://fhirlabs.net/"));
            Assert.False(_diagnosticsChainValidator.Called);
        }

        [Fact]
        public async Task UdapClientDiscoveryForMeditechFhirServer()
        {
            var udapClient = await GetUdapClient();
            udapClient.TokenError += message =>
            {
                _testOutputHelper.WriteLine($"Token Error: {message}");
            };
            
            var result = await udapClient.ValidateResource("https://dev-mtx-interop.meditech.com", "urn:oid:4.5.6");
            Assert.False(result.IsError, result.Error);

            var metaData = udapClient.UdapServerMetadata;
            Assert.NotNull(metaData);
        }

        [Fact]
        public async Task UdapClientDiscoveryForHealthToGo()
        {
            var client = new HttpClient();
            var disco = await client.GetUdapDiscoveryDocument(new UdapDiscoveryDocumentRequest()
            {
                Address = "https://stage.healthtogo.me:8181/fhir/r4/stage",
                Policy = new DiscoveryPolicy
                {
                    ValidateEndpoints = false   // Authority endpoints are not hosted on same domain as Identity Provider.
                }
            });

            // var discoJsonFormatted = JsonSerializer.Serialize(disco.Json, new JsonSerializerOptions { WriteIndented = true });
            // _testOutputHelper.WriteLine(discoJsonFormatted);

            var metadata = disco.Json?.Deserialize<UdapMetadata>();

            var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
            var tokenHeader = jwt.Header;
            // _testOutputHelper.WriteLine(tokenHeader.X5c);
            var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray()!;
            
#if NET9_0_OR_GREATER
            var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5CArray.First()!.ToString()));
#else
            var cert = new X509Certificate2(Convert.FromBase64String(x5CArray.First()!.ToString()));
#endif
            var tokenHandler = new JwtSecurityTokenHandler();
            
            tokenHandler.ValidateToken(metadata.SignedMetadata, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = ["https://stage.healthtogo.me:8181/fhir/r4/stage"], //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
                ValidateAudience = false, // No aud for UDAP metadata
                ValidateLifetime = true,
                IssuerSigningKey = new X509SecurityKey(cert),
                ValidAlgorithms = [tokenHeader.Alg], //must match signing algorithm
            
            }, out _);
            
            var problemFlags = ChainProblemStatus.NotTimeValid |
                               ChainProblemStatus.Revoked |
                               ChainProblemStatus.NotSignatureValid |
                               ChainProblemStatus.InvalidBasicConstraints |
                               ChainProblemStatus.OfflineRevocation;
            
            Assert.True(await ValidateCertificateChain(cert, problemFlags, "https://stage.healthtogo.me:8181"));
            Assert.False(_diagnosticsChainValidator.Called);
        }


        public async Task<IUdapClient> GetUdapClient()
        {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", false, true)
                .AddUserSecrets<GeneralTests>()
                .Build();

            var services = new ServiceCollection();

            services.AddScoped<TrustChainValidator>();
            services.AddScoped<UdapClientDiscoveryValidator>();
            services.AddHttpClient<IUdapClient, UdapClient>()
                .AddHttpMessageHandler(sp =>
                    new HeaderAugmentationHandler(sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>()));

            services.TryAddSingleton<IUdapMetadataOptionsProvider, UdapMetadataOptionsProvider>();

            // UDAP CertStore
            services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Common.Constants.UdapFileCertStoreManifestSectionName));
            services.AddSingleton<ITrustAnchorStore>(sp =>
                new TrustAnchorFileStore(
                    sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                    Substitute.For<ILogger<TrustAnchorFileStore>>()));

            var sp = services.BuildServiceProvider();

            return sp.GetRequiredService<IUdapClient>();
        }

        public async Task<bool> ValidateCertificateChain(
            X509Certificate2 issuedCertificate2,
            ChainProblemStatus problemFlags,
            string communityName)
        {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", false, true)
                .AddUserSecrets<GeneralTests>()
            .Build();

            var services = new ServiceCollection();

            services.TryAddSingleton<IUdapMetadataOptionsProvider, UdapMetadataOptionsProvider>();

            // UDAP CertStore
            services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Common.Constants.UdapFileCertStoreManifestSectionName));
            services.AddSingleton<ITrustAnchorStore>(sp =>
                new TrustAnchorFileStore(
                    sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                    Substitute.For<ILogger<TrustAnchorFileStore>>()));


            var sp = services.BuildServiceProvider();
            var certStore = sp.GetRequiredService<ITrustAnchorStore>();
            var certificateStore = await certStore.Resolve();
            var anchors = certificateStore.AnchorCertificates
                .Where(c => c.Community == communityName)
                .ToList();

            var intermediates = anchors
                .SelectMany(a => a.Intermediates!.Select(i => X509Certificate2.CreateFromPem(i.Certificate))).ToArray()
                .ToX509Collection();

            var anchorCertificates = anchors
                .Select(c => X509Certificate2.CreateFromPem(c.Certificate))
                .OrderBy(certificate => certificate.NotBefore)
                .ToArray()
                .ToX509Collection();

            var validator = new TrustChainValidator(
                problemFlags,
                false, // no revocation checking in tests
                _testOutputHelper.ToLogger<TrustChainValidator>());
            validator.Problem += _diagnosticsChainValidator.OnChainProblem;

            // Help while writing tests to see problems summarized.
            validator.Error += (_, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
            validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.Problems.Summarize(problemFlags));
            validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);

            return await validator.IsTrustedCertificateAsync(
                "client_name",
                issuedCertificate2,
                intermediates,
                anchorCertificates!);
        }

        public class FakeChainValidatorDiagnostics
        {
            public bool Called;

            private readonly List<string> _actualErrorMessages = new List<string>();
            public List<string> ActualErrorMessages
            {
                get { return _actualErrorMessages; }
            }

            public void OnChainProblem(ChainElementInfo chainElement)
            {
                foreach (var problem in chainElement.Problems
                             .Where(p => (p.Status & TrustChainValidator.DefaultProblemFlags) != 0))
                {
                    var msg = $"Trust ERROR ({problem.Status}){problem.StatusInformation}, {chainElement.Certificate}";
                    _actualErrorMessages.Add(msg);
                    Called = true;
                }
            }
        }
    }
}