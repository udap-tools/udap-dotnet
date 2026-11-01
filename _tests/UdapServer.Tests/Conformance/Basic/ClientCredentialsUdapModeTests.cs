#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using NSubstitute;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Udap.Client;
using Udap.Client.Extensions;
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Configuration;
using Udap.Server.Storage;
using Udap.Server.Validation;
using UdapServer.Tests.Common;
using Xunit.Abstractions;
using JwtHeaderParameterNames = Microsoft.IdentityModel.JsonWebTokens.JwtHeaderParameterNames;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Auth.Server")]
public class ClientCredentialsUdapModeTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly UdapAuthServerPipeline _mockPipeline = new UdapAuthServerPipeline();

    public ClientCredentialsUdapModeTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

        var anchorCommunity2 = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/caLocalhostCert2.cer");
        var intermediateCommunity2 = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/intermediateLocalhostCert2.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

        var anchorCommunity2 = new X509Certificate2("CertStore/anchors/caLocalhostCert2.cer");
        var intermediateCommunity2 = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert2.cer");
#endif

        _mockPipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(new ServerSettings
            {
                DefaultUserScopes = "udap",
                DefaultSystemScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1 // Support both V1 and V2 for backward compatibility
            });

            services.AddSingleton<IOptionsMonitor<UdapClientOptions>>(new OptionsMonitorForTests<UdapClientOptions>(
                new UdapClientOptions
                {
                    ClientName = "Mock Client",
                    Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }

                })
            );

            //
            // Ensure IUdapClient uses the TestServer's HttpMessageHandler
            // Wired up via _mockPipeline.BrowserClient
            //
            services.AddScoped<IUdapClient>(sp => new UdapClient(
                _mockPipeline.BrowserClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));

        };

        _mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            s.AddSingleton(_mockPipeline.Clients);
        };

        _mockPipeline.Initialize(enableLogging: true);
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockPipeline.Communities.Add(new Community
        {
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors =
            [
                new Anchor(sureFhirLabsAnchor, "udap://fhirlabs.net")
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new Intermediate(intermediateCert)
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Enabled = true
                        }
                    }
                }
            ]
        });

        _mockPipeline.Communities.Add(new Community
        {
            Name = "localhost_fhirlabs_community2",
            Enabled = true,
            Default = false,
            Anchors =
            [
                new Anchor(anchorCommunity2, "localhost_fhirlabs_community2")
                {
                    BeginDate = anchorCommunity2.NotBefore.ToUniversalTime(),
                    EndDate = anchorCommunity2.NotAfter.ToUniversalTime(),
                    Name = anchorCommunity2.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new Intermediate(intermediateCommunity2)
                        {
                            BeginDate = intermediateCommunity2.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCommunity2.NotAfter.ToUniversalTime(),
                            Name = intermediateCommunity2.Subject,
                            Enabled = true
                        }
                    }
                }
            ]
        });
        

        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        _mockPipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes("system/Patient.rs"));
        _mockPipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes(" system/Appointment.rs"));
    }

    [Fact]
    public async Task GetAccessToken()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        var b2bHl7 = new HL7B2BAuthorizationExtension()
        {
            SubjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890",
            OrganizationId = new Uri("https://fhirlabs.net/fhir/r4").OriginalString,
            OrganizationName = "FhirLabs",
            PurposeOfUse = new List<string>
            {
                "urn:oid:2.16.840.1.113883.5.8#TREAT"
            }
            // },
            // ConsentReference = new HashSet<string>{
            //     "https://fhirlabs.net/fhir/r4"
            // }
        };

        //
        // Get Access Token
        //
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regDocumentResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .WithClaim(new Claim("Random_Claim", "udap"))
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2bHl7) 
            .Build("RS384");

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);
    }



    [Fact]
    public async Task GetAccessToken_Rollover_Expired_Secret()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        //
        // Now lets set the Client Secret entry in the database to an expired entry.
        //
        var client = _mockPipeline.Clients.Single(c => c.ClientId == regDocumentResult.ClientId);
        foreach (var secret in client.ClientSecrets)
        {
            secret.Expiration = DateTime.Now + TimeSpan.FromDays(-1);
        }

        //
        // Get Access Token
        //
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regDocumentResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.Equal("system/Patient.rs", tokenResponse.Scope);

        client = _mockPipeline.Clients.Single(c => c.ClientId == regDocumentResult.ClientId);
        foreach (var secret in client.ClientSecrets)
        {
            _testOutputHelper.WriteLine(secret.Expiration.ToString());
        }
    }

    /// <summary>
    /// Regression: only the UDAP_SAN_URI_ISS_NAME and UDAP_COMMUNITY secrets are expired while the
    /// UDAP_X509_CERTIFICATE secret is still current. Duende filters the expired secrets before the
    /// secret validator runs, so the validator sees a non-empty list with no community. It must still
    /// roll the identity secrets forward instead of failing with "No trust anchors available".
    /// </summary>
    [Fact]
    public async Task GetAccessToken_Rollover_Expired_Identity_Secrets_With_Current_Certificate_Secret()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        var client = _mockPipeline.Clients.Single(c => c.ClientId == regDocumentResult.ClientId);
        Assert.Contains(client.ClientSecrets, s => s.Type == UdapServerConstants.SecretTypes.UDAP_X509_CERTIFICATE);

        foreach (var secret in client.ClientSecrets.Where(s =>
                     s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME ||
                     s.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY))
        {
            secret.Expiration = DateTime.UtcNow.AddDays(-1);
        }

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regDocumentResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.False(tokenResponse.IsError, tokenResponse.Error + " " + tokenResponse.ErrorDescription);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);

        client = _mockPipeline.Clients.Single(c => c.ClientId == regDocumentResult.ClientId);
        foreach (var secret in client.ClientSecrets.Where(s =>
                     s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME ||
                     s.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY))
        {
            Assert.Equal(clientCert.NotAfter.ToUniversalTime(), secret.Expiration);
        }
    }



    [Fact]
    public async Task GetAccessToken_Without_algorithm()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            regDocumentResult.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, regDocumentResult.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                    ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384");

        var jwt = new JsonWebToken(clientAssertion);
        var jObject = JObject.Parse(Base64UrlEncoder.Decode(jwt.EncodedHeader));
        //
        // Break it
        //
        jObject.Remove(JwtHeaderParameterNames.Alg);
        var header = Base64UrlEncoder.Encode(jObject.ToString());
        clientAssertion = $"{header}.{jwt.EncodedPayload}.{jwt.EncodedSignature}";
        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs"
        };

        
        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        
        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.Equal(ResponseErrorType.Protocol, tokenResponse.ErrorType);
    }

    /// <summary>
    /// UDAP JWT-Based Client Authentication section 6.3 recommends a maximum
    /// Authentication Token lifetime of 5 minutes. An unexpired assertion whose
    /// exp is one hour past a valid iat must still be rejected.
    /// </summary>
    [Fact]
    public async Task GetAccessToken_ClientAssertion_exp_ExceedsMaxLifetime()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        //
        // Get Access Token with a client assertion valid for one hour
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            regDocumentResult.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, regDocumentResult.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                    ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
            },
            now.ToUniversalTime(),
            now.AddHours(1).ToUniversalTime()
        );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384");

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.NotNull(tokenResponse.ErrorDescription);
        Assert.Contains("exceeds the maximum lifetime of 300 seconds from iat", tokenResponse.ErrorDescription);
    }

    [Fact]
    public async Task GetAccessToken_Without_x5c()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            regDocumentResult.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, regDocumentResult.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                    ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384");

        var jwt = new JsonWebToken(clientAssertion);
        var jObject = JObject.Parse(Base64UrlEncoder.Decode(jwt.EncodedHeader));
        //
        // Break it
        //
        jObject.Remove(JwtHeaderParameterNames.X5c);
        var header = Base64UrlEncoder.Encode(jObject.ToString());
        clientAssertion = $"{header}.{jwt.EncodedPayload}.{jwt.EncodedSignature}";
        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs"
        };
        
        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.Equal(ResponseErrorType.Protocol, tokenResponse.ErrorType);
    }

    //Sign with RS384 but set the header alg claim to RS256
    [Fact]
    public async Task GetAccessToken_With_invalid_alg()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            regDocumentResult.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, regDocumentResult.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                    ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384"); 

        var jwt = new JsonWebToken(clientAssertion);
        var jObject = JObject.Parse(Base64UrlEncoder.Decode(jwt.EncodedHeader));
        //
        // Break it
        //
        jObject.Property(JwtHeaderParameterNames.Alg)!.Value = "RS256"; // Does not match 

        var header = Base64UrlEncoder.Encode(jObject.ToString());

        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, "RS384");
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(header, ".", jwt.EncodedPayload),
                signingCredentials);

        clientAssertion = $"{header}.{jwt.EncodedPayload}.{encodedSignature}";

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs"
        };


        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        
        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.Equal(ResponseErrorType.Protocol, tokenResponse.ErrorType);
    }

    [Fact]
    public async Task GetAccessToken_Without_iss()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var jwtPayload = new JwtPayLoadExtension(
            regDocumentResult.ClientId,
            IdentityServerPipeline.TokenEndpoint,
            new List<Claim>()
            {
                new Claim(JwtClaimTypes.Subject, regDocumentResult.ClientId!),
                new Claim(JwtClaimTypes.IssuedAt, EpochTime.GetIntDate(now.ToUniversalTime()).ToString(),
                    ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId()),
                // new Claim(UdapConstants.JwtClaimTypes.Extensions, BuildHl7B2BExtensions() ) //see http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
            },
            now.ToUniversalTime(),
            now.AddMinutes(5).ToUniversalTime()
        );

        var clientAssertion =
            SignedSoftwareStatementBuilder<JwtPayLoadExtension>
                .Create(clientCert, jwtPayload)
                .Build("RS384");

        var jwt = new JsonWebToken(clientAssertion);
        var jObject = JObject.Parse(Base64UrlEncoder.Decode(jwt.EncodedPayload));
        //
        // Break it
        //
        jObject.Remove(JwtClaimTypes.Issuer);
        var encodedPayload = Base64UrlEncoder.Encode(jObject.ToString());

        var securityKey = new X509SecurityKey(clientCert);
        var signingCredentials = new SigningCredentials(securityKey, "RS384");
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(jwt.EncodedHeader, ".", encodedPayload),
                signingCredentials);

        clientAssertion = $"{jwt.EncodedHeader}.{encodedPayload}.{encodedSignature}";


        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            //ClientId = result.ClientId, we use Implicit ClientId in the iss claim
            ClientAssertion = new ClientAssertion()
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.Equal(ResponseErrorType.Protocol, tokenResponse.ErrorType);
    }

    [Fact]
    public async Task GetAccessTokenECDSA_ES256()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.ecdsa.client.pfx", "udap-test",
            X509KeyStorageFlags.Exportable);
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.ecdsa.client.pfx", "udap-test",
            X509KeyStorageFlags.Exportable);
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());


        //
        // Get Access Token
        //
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regDocumentResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("ES256");

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
        
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);

    }

    [Fact]
    public async Task GetAccessTokenECDSA_ES384()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.ecdsa.client.pfx", "udap-test",
            X509KeyStorageFlags.Exportable);
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.ecdsa.client.pfx", "udap-test",
            X509KeyStorageFlags.Exportable);
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());


        //
        // Get Access Token
        //
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regDocumentResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build(UdapConstants.SupportedAlgorithm.ES384);

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.Equal("system/Patient.rs", tokenResponse.Scope);

    }

    [Fact]
    public async Task UpdateRegistration()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        //
        // First Registration
        //
        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        //
        // Typically the client would validate a server before proceeding to registration.
        //
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());
        Assert.Equal("system/Patient.rs", regDocumentResult.Scope);

        var clientIdWithDefaultSubAltName = regDocumentResult.ClientId;

        //
        // Second Registration
        //
        regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs system/Appointment.rs");

        Assert.Null(regDocumentResult.GetError());
        Assert.Equal("system/Appointment.rs system/Patient.rs", regDocumentResult.Scope);

        Assert.Equal(clientIdWithDefaultSubAltName, regDocumentResult.ClientId);

        //
        // Third Registration with different Uri Subject Alt Name from same client certificate
        // expect 201 created because I changed the SAN selected by calling WithIssuer
        //
        var regDocumentResultForSelectedSubAltName = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs system/Appointment.rs",
            "https://fhirlabs.net:7016/fhir/r4");
        
        Assert.Equal("system/Appointment.rs system/Patient.rs", regDocumentResultForSelectedSubAltName.Scope);
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        Assert.NotEqual(clientIdWithDefaultSubAltName, clientIdWithSelectedSubAltName);

        //
        // Fourth Registration with Uri Subject Alt Name from third registration
        // expect 200 OK because I changed scope
        //
        var regDocumentResultForSelectedSubAltNameSecond = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs",
            "https://fhirlabs.net:7016/fhir/r4");
        
        Assert.Equal("system/Patient.rs", regDocumentResultForSelectedSubAltNameSecond.Scope);
        Assert.Equal(clientIdWithSelectedSubAltName, regDocumentResultForSelectedSubAltNameSecond.ClientId);

    }

   
    [Fact]
    public async Task CancelRegistration()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        //
        // Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal("system/Patient.rs", regDocumentResult!.Scope);

        var clientIdWithDefaultSubAltName = regDocumentResult.ClientId!;

        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );
        

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.OK, regResponse.StatusCode); // Deleted finished so returns a 200 status code according to udap.org specifications
        
        //
        // Even during a cancel registration it is expected that he SoftwareStatement returned is the same.
        //
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal(signedSoftwareStatement, regDocumentResult!.SoftwareStatement);
        Assert.Equal("removed", regDocumentResult.ClientId); 

        //
        // Repeated un-register should be 400 rather than not found (404).
        // This is following section 5.2 of https://www.udap.org/udap-dynamic-client-registration.html
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.BadRequest, regResponse.StatusCode); 

        //
        // Registration with different Uri Subject Alt Name from same client certificate
        // expect 201 created because I changed the SAN selected by calling WithIssuer
        //

        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);
        var regDocumentResultForSelectedSubAltName =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal("system/Appointment.rs system/Patient.rs", regDocumentResultForSelectedSubAltName!.Scope);
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        Assert.NotEqual(clientIdWithDefaultSubAltName, clientIdWithSelectedSubAltName);

        
        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.OK, regResponse.StatusCode); // Deleted finished so returns a 200 status code according to udap.org specifications
        //
        // Even during a cancel registration it is expected that he SoftwareStatement returned is the same.
        //
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal(signedSoftwareStatement, regDocumentResult!.SoftwareStatement);
        // Assert.Equal(clientIdWithSelectedSubAltName, regDocumentResult.ClientId);  //with a cancel it is possible to delete multiple client ids.
        //
        // Repeated un-register should be 400 rather than not found (404).
        // This is following section 5.2 of https://www.udap.org/udap-dynamic-client-registration.html
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.BadRequest, regResponse.StatusCode); // Deleted finished so returns a 404 status code
    }

    [Fact]
    public async Task RegisterTwoCommunitiesWithSameISS_AndCancelOne()
    {
#if NET9_0_OR_GREATER
        var clientCert1 = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var clientCert2 = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirLabsApiClientLocalhostCert2.pfx", "udap-test");
#else
        var clientCert1 = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var clientCert2 = new X509Certificate2("CertStore/issued/fhirLabsApiClientLocalhostCert2.pfx", "udap-test");
#endif

        //
        // Register Client 1 from community "udap://fhirlabs.net"
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert1)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert1, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal("system/Patient.rs", regDocumentResult!.Scope);
        
        //
        // Register Client 2 from community "localhost_fhirlabs_community2"
        //
        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert2)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test 2")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert2, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal("system/Patient.rs", regDocumentResult!.Scope);

        Assert.Equal(2, _mockPipeline.Clients.Count);

        //
        // Cancel Registration from community "udap://fhirlabs.net"
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert1)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert1, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );


        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.OK, regResponse.StatusCode); // Deleted finished so returns a 200 status code according to udap.org specifications


        //Store validation
        Assert.Single(_mockPipeline.Clients);

    }

    [Fact]
    public async Task Missing_grant_types_RegistrationResultsIn_invalid_client()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        //
        // Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal("system/Patient.rs", regDocumentResult!.Scope);

        var clientIdWithDefaultSubAltName = regDocumentResult.ClientId;

        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );



        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.OK, regResponse.StatusCode); // Deleted finished so returns a 200 status code according to udap.org specifications

        //
        // Even during a cancel registration it is expected that he SoftwareStatement returned is the same.
        //
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal(signedSoftwareStatement, regDocumentResult!.SoftwareStatement);
        // Assert.Equal(clientIdWithDefaultSubAltName, regDocumentResult.ClientId);  //with a cancel it is possible to delete multiple client ids.

        //
        // Repeated un-register should be 400 rather than not found (404).
        // This is following section 5.2 of https://www.udap.org/udap-dynamic-client-registration.html
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.BadRequest, regResponse.StatusCode); // Deleted finished so returns a 204 status code

        //
        // Registration with different Uri Subject Alt Name from same client certificate
        // expect 201 created because I changed the SAN selected by calling WithIssuer.
        // I can have a new registration if identifying a different SAN
        //

        document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs system/Appointment.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);
        var regDocumentResultForSelectedSubAltName =
            await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal("system/Appointment.rs system/Patient.rs", regDocumentResultForSelectedSubAltName!.Scope);
        var clientIdWithSelectedSubAltName = regDocumentResultForSelectedSubAltName.ClientId;
        Assert.NotEqual(clientIdWithDefaultSubAltName, clientIdWithSelectedSubAltName);


        //
        // Cancel Registration
        //
        document = UdapDcrBuilderForClientCredentials
            .Cancel(clientCert)
            .WithIssuer(new Uri("https://fhirlabs.net:7016/fhir/r4"))
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.OK, regResponse.StatusCode); // Deleted finished so returns a 200 status code according to udap.org specifications
        //
        // Even during a cancel registration it is expected that he SoftwareStatement returned is the same.
        //
        regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal(signedSoftwareStatement, regDocumentResult!.SoftwareStatement);
        // Assert.Equal(clientIdWithSelectedSubAltName, regDocumentResult.ClientId);  //with a cancel it is possible to delete multiple client ids.
        //
        // Repeated un-register should be 400 rather than not found (404).
        // This is following section 5.2 of https://www.udap.org/udap-dynamic-client-registration.html
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.BadRequest, regResponse.StatusCode); // Deleted finished so returns a 404 status code
    }

    [Fact]
    public async Task ReplayRegistration()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        //
        // First Registration
        //
        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal("system/Patient.rs", regDocumentResult!.Scope);



        //
        // Second Registration
        //
        regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.BadRequest, regResponse.StatusCode);
        var errorResult = await regResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.NotNull(errorResult);
        Assert.Equal("invalid_client_metadata", errorResult.Error);
        Assert.Equal("software_statement replayed", errorResult.ErrorDescription);
        
    }

    /// <summary>
    /// A UDAP-registered client whose trust chain can no longer be validated at token time (anchor
    /// disabled/rotated, revocation failure, etc.) must be rejected — even though the pipeline also
    /// registers Duende's AddJwtBearerClientAuthentication() for non-UDAP private_key_jwt clients.
    /// Guards against UDAP client cert secrets being stored under Duende's X509CertificateBase64
    /// secret type, which let the stock PrivateKeyJwtSecretValidator validate the assertion by
    /// signature alone and bypass UDAP trust-chain enforcement.
    /// </summary>
    [Fact]
    public async Task GetAccessToken_Fails_When_TrustChainInvalid_Despite_JwtBearerClientAuthentication()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        //
        // Break the trust chain at token time: remove every community's anchors so chain resolution
        // fails. (Disabling the community is not enough — the token-time lookup resolves the client's
        // community by id and does not consult Enabled.)
        //
        foreach (var community in _mockPipeline.Communities)
        {
            community.Anchors = new List<Anchor>();
        }

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regDocumentResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError,
            "token was issued even though the UDAP trust chain could not be validated — " +
            "the stock PrivateKeyJwtSecretValidator must not be able to validate UDAP client secrets");
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    /// <summary>
    /// Pins the type separation: UDAP registration must store the client certificate under the
    /// UDAP-specific secret type, never Duende's X509CertificateBase64 (see test above for why).
    /// </summary>
    [Fact]
    public async Task Registration_Stores_Certificate_Under_Udap_Secret_Type()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif

        var udapClient = _mockPipeline.Resolve<IUdapClient>();
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regDocumentResult.GetError());

        var registeredClient = _mockPipeline.Clients.Single(c => c.ClientId == regDocumentResult.ClientId);
        var certSecrets = registeredClient.ClientSecrets
            .Where(s => s.Value == Convert.ToBase64String(clientCert.RawData))
            .ToList();

        Assert.NotEmpty(certSecrets);
        Assert.All(certSecrets, s =>
        {
            Assert.Equal(Udap.Server.Storage.UdapServerConstants.SecretTypes.UDAP_X509_CERTIFICATE, s.Type);
            Assert.NotEqual(IdentityServerConstants.SecretTypes.X509CertificateBase64, s.Type);
        });
    }

    /// <summary>
    /// Don't forget to add .AddJwtBearerClientAuthentication() to the IdentityServer configuration
    /// if you are going to enable compact JWS that are not UDAP.  They can coexist with UDAP
    /// in your client store.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task GetAccessToken_With_Standard_X509CertificateBase64_Secret()
    {
#if NET9_0_OR_GREATER
        var clientCert = X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
        var clientId = "test_client_x509";

        _mockPipeline.Clients.Add(new Client
        {
            ClientId = clientId,
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            AllowedScopes = { "system/Patient.rs" },
            RequireClientSecret = true,
            ClientSecrets = new List<Secret>
            {
                new Secret(Convert.ToBase64String(clientCert.RawData), "Test X509 Cert")
                {
                    Type = IdentityServerConstants.SecretTypes.X509CertificateBase64
                }
            }
        });

        //
        // Get Access Token
        //
        var now = DateTime.UtcNow;
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Subject = new ClaimsIdentity(new[] { new Claim(JwtClaimTypes.Subject, clientId) }),
            Audience = IdentityServerPipeline.TokenEndpoint,
            Expires = now.AddMinutes(5),
            IssuedAt = now,
            NotBefore = now,
            SigningCredentials = new SigningCredentials(new X509SecurityKey(clientCert), "RS384"),
            Claims = new Dictionary<string, object> { { JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId() } }
        };

        var tokenHandler = new JsonWebTokenHandler();
        var clientAssertion = tokenHandler.CreateToken(tokenDescriptor);
        _testOutputHelper.WriteLine(clientAssertion);
        var clientRequest = new ClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            ClientId = clientId,
            Scope = "system/Patient.rs",
            ClientCredentialStyle = ClientCredentialStyle.PostBody,
            ClientAssertion = new ClientAssertion
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = clientAssertion
            }
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.RequestClientCredentialsTokenAsync(clientRequest);

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);
    }

    /// <summary>
    /// The client assertion must be signed by x5c[0], the certificate whose trust chain is validated
    /// (UDAP JWT-Based Client Authentication section 6.1). Here x5c[0] is the registered client's own
    /// certificate and a self-signed certificate follows it; an assertion signed with the self-signed
    /// key must not authenticate the client.
    /// </summary>
    [Fact]
    public async Task GetAccessToken_Signed_By_Another_x5c_Certificate_Is_Rejected()
    {
        var clientCert = LoadPfx("CertStore/issued/fhirlabs.net.client.pfx");
        var regDocumentResult = await RegisterClientCredentialsClient(clientCert);

        using var otherKey = RSA.Create(2048);
        var otherCertRequest = new CertificateRequest("CN=Not The Client", otherKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var otherCert = otherCertRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

        var now = DateTime.UtcNow;
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = regDocumentResult.ClientId,
            Audience = IdentityServerPipeline.TokenEndpoint,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Claims = new Dictionary<string, object>
            {
                { JwtClaimTypes.Subject, regDocumentResult.ClientId! },
                { JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId() }
            },
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                { JwtHeaderParameterNames.X5c, new[] { Convert.ToBase64String(clientCert.RawData), Convert.ToBase64String(otherCert.RawData) } }
            },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(otherKey), SecurityAlgorithms.RsaSha384)
        };

        var clientRequest = new UdapClientCredentialsTokenRequest
        {
            Address = IdentityServerPipeline.TokenEndpoint,
            ClientAssertion = new ClientAssertion
            {
                Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = new JsonWebTokenHandler().CreateToken(tokenDescriptor)
            },
            Udap = UdapConstants.UdapVersionsSupportedValue,
            Scope = "system/Patient.rs"
        };

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError, "a key from a certificate other than x5c[0] authenticated the client");
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    /// <summary>
    /// A certificate that chains to the client's community but belongs to another member must not
    /// authenticate the client: x5c[0] must carry the URI SAN the client registered with
    /// (UDAP JWT-Based Client Authentication section 6.3).
    /// </summary>
    [Fact]
    public async Task GetAccessToken_With_Another_Community_Members_Certificate_Is_Rejected()
    {
        var clientCert = LoadPfx("CertStore/issued/fhirLabsApiClientLocalhostCert2.pfx");
        var regDocumentResult = await RegisterClientCredentialsClient(clientCert);

        // Same community intermediate, different URI SAN (https://idpserver2).
        var otherMemberCert = LoadPfx("CertStore/issued/idpserver2.pfx");

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regDocumentResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                otherMemberCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError, "another community member's certificate authenticated the client");
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    /// <summary>
    /// Secret rollover only accepts a renewal of the client's own certificate. Another community
    /// member's certificate must neither authenticate the client nor replace its stored certificate.
    /// </summary>
    [Fact]
    public async Task GetAccessToken_Rollover_With_Another_Community_Members_Certificate_Is_Rejected()
    {
        var clientCert = LoadPfx("CertStore/issued/fhirLabsApiClientLocalhostCert2.pfx");
        var regDocumentResult = await RegisterClientCredentialsClient(clientCert);

        var client = _mockPipeline.Clients.Single(c => c.ClientId == regDocumentResult.ClientId);
        foreach (var secret in client.ClientSecrets)
        {
            secret.Expiration = DateTime.Now + TimeSpan.FromDays(-1);
        }

        var otherMemberCert = LoadPfx("CertStore/issued/idpserver2.pfx");

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regDocumentResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                otherMemberCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError, "another community member's certificate authenticated the client through rollover");
        Assert.Equal("invalid_client", tokenResponse.Error);

        var storedCertificate = client.ClientSecrets
            .Single(s => s.Type == UdapServerConstants.SecretTypes.UDAP_X509_CERTIFICATE).Value;
        Assert.Equal(Convert.ToBase64String(clientCert.Export(X509ContentType.Cert)), storedCertificate);
    }

    private async Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient(X509Certificate2 clientCert)
    {
        var udapClient = _mockPipeline.Resolve<IUdapClient>();
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var regDocumentResult = await udapClient.RegisterClientCredentialsClient(clientCert, "system/Patient.rs");
        Assert.Null(regDocumentResult.GetError());

        return regDocumentResult;
    }

    private static X509Certificate2 LoadPfx(string path)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile(path, "udap-test");
#else
        return new X509Certificate2(path, "udap-test");
#endif
    }
}
