
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using FluentAssertions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;


namespace UdapServer.Tests.Common.ConnectaThon;
public class HealthGorillaTests
{

    private readonly ITestOutputHelper _testOutputHelper;
    private const string Category = "Conformance.Basic.UdapResponseTypeResponseModeTests";

    private readonly UdapIdentityServerPipeline _mockPipeline = new UdapIdentityServerPipeline();


    public HealthGorillaTests(ITestOutputHelper testOutputHelper)
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
                DefaultSystemScopes = "udap",
                ForceStateParamOnAuthorizationCode = true
            });
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


    [Fact]
    public async Task RegistrationDocumentFailCertifiationTest()
    {
        var regDocOnWire =
            @"{ ""software_statement"": ""eyJ0eXAiOi..."", ""certifications"": ""[]"", ""udap"": ""1""}";

        JsonSerializer.Deserialize<UdapDynamicClientRegistrationDocument>(regDocOnWire);

        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapIdentityServerPipeline.RegistrationEndpoint,
            new StringContent(regDocOnWire, new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var errorMessage = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        errorMessage.Should().NotBeNull();
        errorMessage!.Error.Should().Be("invalid_client_metadata");
        errorMessage.ErrorDescription.Should().Be("Malformed metadata document");
    }
}
