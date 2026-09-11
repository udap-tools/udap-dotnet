#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Client.Messages;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Server.Models;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Middleware;

/// <summary>
/// <c>UdapAuthorizationResponseMiddleware</c> must behave the same whether the
/// authorization request arrives as a GET query string or as an
/// application/x-www-form-urlencoded POST (SSRAA, FHIR-52960). Every test runs
/// both transports.
/// </summary>
[Collection("Udap.Auth.Server")]
public class UdapAuthorizationResponseMiddlewareTests
{
    private const string Community = "udap://fhirlabs.net";
    private const string RedirectUri = "https://code_client/callback";
    private const string Scopes = "openid udap";

    private readonly ITestOutputHelper _testOutputHelper;

    public UdapAuthorizationResponseMiddlewareTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    public static TheoryData<AuthorizeHttpMethod> Transports => new()
    {
        AuthorizeHttpMethod.Get,
        AuthorizeHttpMethod.Post
    };

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task MissingState_WhenStateIsForced_RedirectsToClientWithError(AuthorizeHttpMethod method)
    {
        var pipeline = BuildPipeline(ForceStateSettings());
        var clientId = await RegisterAuthorizationCodeClientAsync(pipeline, Scopes, RedirectUri);
        await pipeline.LoginAsync("bob");

        var nonce = Guid.NewGuid().ToString();
        var url = pipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: Scopes,
            redirectUri: RedirectUri,
            nonce: nonce); // no state

        var response = await pipeline.BrowserClient.AuthorizeAsync(url, method);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(RedirectUri + "?", response.Headers.Location!.AbsoluteUri);
        _testOutputHelper.WriteLine(response.Headers.Location.AbsoluteUri);

        var query = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Equal("invalid_request", query["error"].ToString());
        Assert.Equal("Missing state", query["error_description"].ToString());
        Assert.Equal("code", query["response_type"].ToString());
        Assert.Equal(Scopes, query["scope"].ToString());
        Assert.Equal(nonce, query["nonce"].ToString());
        Assert.DoesNotContain(query, q => q.Key == "state");
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task UnsupportedResponseType_IsRewrittenToClientRedirect(AuthorizeHttpMethod method)
    {
        var pipeline = BuildPipeline(ForceStateSettings());
        var clientId = await RegisterAuthorizationCodeClientAsync(pipeline, Scopes, RedirectUri);
        await pipeline.LoginAsync("bob");

        var state = Guid.NewGuid().ToString();
        var url = pipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "invalid_response_type",
            scope: Scopes,
            redirectUri: RedirectUri,
            state: state,
            nonce: Guid.NewGuid().ToString());

        var response = await pipeline.BrowserClient.AuthorizeAsync(url, method);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(RedirectUri + "?", response.Headers.Location!.AbsoluteUri);

        var query = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Equal("invalid_request", query["error"].ToString());
        Assert.Equal("Response type not supported", query["error_description"].ToString());
        Assert.Equal("invalid_response_type", query["response_type"].ToString());
        Assert.Equal(state, query["state"].ToString());
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task UnknownClient_ErrorIsRenderedAsBadRequestJson(AuthorizeHttpMethod method)
    {
        var pipeline = BuildPipeline(ForceStateSettings());
        await pipeline.LoginAsync("bob");

        var url = pipeline.CreateAuthorizeUrl(
            clientId: "unknown-client",
            responseType: "code",
            scope: Scopes,
            redirectUri: RedirectUri,
            state: Guid.NewGuid().ToString(),
            nonce: Guid.NewGuid().ToString());

        var response = await pipeline.BrowserClient.AuthorizeAsync(url, method);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        _testOutputHelper.WriteLine(body);
        Assert.Contains("error", body);
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task ValidRequest_AfterLogin_IssuesCode(AuthorizeHttpMethod method)
    {
        var pipeline = BuildPipeline(ForceStateSettings());
        var clientId = await RegisterAuthorizationCodeClientAsync(pipeline, Scopes, RedirectUri);
        await pipeline.LoginAsync("bob");

        var state = Guid.NewGuid().ToString();
        var url = pipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: Scopes,
            redirectUri: RedirectUri,
            state: state,
            nonce: Guid.NewGuid().ToString());

        var response = await pipeline.BrowserClient.AuthorizeAsync(url, method);

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.StartsWith(RedirectUri + "?", response.Headers.Location!.AbsoluteUri);

        var query = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Contains(query, q => q.Key == "code");
        Assert.Equal(state, query["state"].ToString());
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task TieredIdp_MissingUdapScope_RedirectsToClientWithError(AuthorizeHttpMethod method)
    {
        var settings = ForceStateSettings();
        settings.TieredIdp = true;
        var pipeline = BuildPipeline(settings);
        var clientId = await RegisterAuthorizationCodeClientAsync(pipeline, Scopes, RedirectUri);
        await pipeline.LoginAsync("bob");

        var state = Guid.NewGuid().ToString();
        var url = pipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: "openid", // udap scope missing
            redirectUri: RedirectUri,
            state: state,
            nonce: Guid.NewGuid().ToString());

        var response = await pipeline.BrowserClient.AuthorizeAsync(url, method);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(RedirectUri + "?", response.Headers.Location!.AbsoluteUri);

        var query = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Equal("invalid_request", query["error"].ToString());
        Assert.Equal(
            "Missing udap and/or openid scope between data holder and IdP",
            query["error_description"].ToString());
        Assert.Equal(state, query["state"].ToString());
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task RedirectUriWithQuery_ErrorRedirectAppendsAndEncodes(AuthorizeHttpMethod method)
    {
        const string redirectUriWithQuery = RedirectUri + "?tenant=a";

        var pipeline = BuildPipeline(ForceStateSettings());
        var clientId = await RegisterAuthorizationCodeClientAsync(pipeline, Scopes, redirectUriWithQuery);
        await pipeline.LoginAsync("bob");

        var url = pipeline.CreateAuthorizeUrl(
            clientId: clientId,
            responseType: "code",
            scope: Scopes,
            redirectUri: redirectUriWithQuery,
            nonce: Guid.NewGuid().ToString()); // no state

        var response = await pipeline.BrowserClient.AuthorizeAsync(url, method);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.AbsoluteUri;
        _testOutputHelper.WriteLine(location);

        // The existing query survives and the error parameters are appended, not stacked behind a second '?'.
        Assert.StartsWith(redirectUriWithQuery + "&error=invalid_request&error_description=Missing%20state", location);
        Assert.Equal(1, location.Count(c => c == '?'));

        var query = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Equal("a", query["tenant"].ToString());
        Assert.Equal("Missing state", query["error_description"].ToString());
    }

    #region Helpers

    private static ServerSettings ForceStateSettings() => new()
    {
        DefaultUserScopes = "user/*.read",
        DefaultSystemScopes = "system/*.read",
        ForceStateParamOnAuthorizationCode = true,
        RequireConsent = false,
        RequirePkce = false,
        SsraaVersion = SsraaVersion.V1_1
    };

    private static X509Certificate2 LoadClientCert()
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#else
        return new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
#endif
    }

    private static async Task<string> RegisterAuthorizationCodeClientAsync(
        UdapAuthServerPipeline pipeline,
        string scope,
        string redirectUri)
    {
        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(LoadClientCert())
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("authorize middleware test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope(scope)
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { redirectUri })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue);

        pipeline.BrowserClient.AllowAutoRedirect = true;

        var response = await pipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(resultDocument?.ClientId);

        pipeline.BrowserClient.AllowAutoRedirect = false;

        return resultDocument!.ClientId!;
    }

    private static UdapAuthServerPipeline BuildPipeline(ServerSettings serverSettings)
    {
        var pipeline = new UdapAuthServerPipeline();

#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        pipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton(serverSettings);

            s.AddSingleton(new UdapClientOptions
            {
                ClientName = "Mock Client",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
            });
        };

        pipeline.OnPreConfigureServices += (_, s) =>
        {
            s.AddSingleton(pipeline.Clients);
        };

        pipeline.Initialize(enableLogging: true);
        pipeline.BrowserClient.AllowAutoRedirect = false;

        pipeline.Communities.Add(new Community
        {
            Name = Community,
            Enabled = true,
            Default = true,
            Anchors =
            [
                new Anchor(sureFhirLabsAnchor, Community)
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>
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

        pipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        pipeline.IdentityScopes.Add(new IdentityResources.Profile());
        pipeline.ApiScopes.Add(new UdapApiScopes.Udap());

        pipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            ]
        });

        return pipeline;
    }

    #endregion
}
