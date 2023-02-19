#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

//
// The following test and pipeline technique are from the original Duende source code tests.
// I will be adapting these to test UDAP specific features where some of the tests are identical
// as I do want the resulting UDAP features to live in harmony with the existing Identity Server.
//

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Server.Services;
using Udap.Server.Services.Default;
using Udap.Server.Validation.Default;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;


namespace UdapServer.Tests.Conformance.Basic;
public class UdapForceStateParamFalseTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private const string Category = "Conformance.Basic.UdapResponseTypeResponseModeTests";

    private UdapIdentityServerPipeline _mockPipeline = new UdapIdentityServerPipeline();

    public UdapForceStateParamFalseTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
        var rootCert = new X509Certificate2("CertStore/roots/SureFhirLabs_CA.cer");
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_Anchor.cer");

        _mockPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton<ServerSettings>(new ServerSettings
            {
                ServerSupport = ServerSupport.UDAP,
                DefaultUserScopes = "udap",
                DefaultSystemScopes = "udap"
                // ForceStateParamOnAuthorizationCode = false (default)
            });

            s.AddTransient<IClientSecretValidator, UdapClientSecretValidator>();
            s.AddSingleton<IScopeService, DefaultScopeService>();
        };

        _mockPipeline.OnPreConfigureServices += s =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // TODO: PR Deunde for this issue.
            // They register Clients as IEnumerable<Client> in AddInMemoryClients extension
            s.AddSingleton(_mockPipeline.Clients);
        };

        _mockPipeline.Initialize(enableLogging: true);
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockPipeline.Clients.Add(new Client
        {
            Enabled = true,
            ClientId = "code_client",
            ClientSecrets = new List<Secret>
            {
                new Secret("secret".Sha512())
            },

            AllowedGrantTypes = GrantTypes.Code,
            AllowedScopes = { "openid" },

            RequireConsent = false,
            RequirePkce = false,
            RedirectUris = new List<string>
            {
                "https://code_client/callback"
            }
        });
        
        _mockPipeline.Communities.Add(new Community
        {
            Name = "udap://surefhir.labs",
            Enabled = true,
            Default = true,
            Anchors = new[] {new Anchor
            {
                BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                Name = sureFhirLabsAnchor.Subject,
                Community = "udap://surefhir.labs",
                Certificate = sureFhirLabsAnchor.ToPemFormat(),
                Thumbprint = sureFhirLabsAnchor.Thumbprint,
                Enabled = true
            }}
        });

        _mockPipeline.RootCertificates.Add(new RootCertificate
        {
            BeginDate = rootCert.NotBefore.ToUniversalTime(),
            EndDate = rootCert.NotAfter.ToUniversalTime(),
            Name = rootCert.Subject,
            Certificate = rootCert.ToPemFormat(),
            Thumbprint = rootCert.Thumbprint,
            Enabled = true
        });

        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        _mockPipeline.ApiScopes.Add(new ApiScope("udap"));

        _mockPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims = new Claim[]
            {
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            }
        });
    }

    /// <summary>
    /// If client does not include the state during connect/authorize and
    /// <see cref="ServerSettings.ForceStateParamOnAuthorizationCode"/> is false (default)
    /// authorize will succeed.
    /// </summary>
    [Fact]
    [Trait("Category", Category)]
    public async Task Request_state_missing_results_in_success()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockPipeline.LoginAsync("bob");
        
        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapIdentityServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string?>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("udap")
            .WithResponseTypes(new List<string?> { "code" })
            .WithRedirectUrls(new List<string?> { "https://code_client/callback" })
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;


        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument!.ClientId!,
            responseType: "code",
            scope: "udap",
            redirectUri: "https://code_client/callback",
            // state: state, //missing state
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain("https://code_client/callback");
        _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "code");
        queryParams.Single(q => q.Key == "scope").Value.Should().BeEquivalentTo("udap");
        queryParams.Count(q => q.Key == "state").Should().Be(0);
    }
}
