
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
        var rootCert = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

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

        _mockPipeline.IntermediateCertificates.Add(new IntermediateCertificate
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

    [Fact (Skip = "TODO: I need a way to inject TokenValidationParameters to test this.  Like setting ValidateLifetime to false.")]
    public async Task RegistrationDocumentInvalidJsonTokenTest()
    {
        var regDocOnWire =
            @"{ ""software_statement"": ""eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlFOWpDQ0E5NmdBd0lCQWdJSWZMMUxyampUTUZnd0RRWUpLb1pJaHZjTkFRRUxCUUF3Z2FNeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlEQUpEUVRFU01CQUdBMVVFQnd3SlUyRnVJRVJwWldkdk1STXdFUVlEVlFRS0RBcEZUVklnUkdseVpXTjBNVFl3TkFZRFZRUUxEQzFEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVTQW9ZMlZ5ZEhNdVpXMXlaR2x5WldOMExtTnZiU2t4SmpBa0JnTlZCQU1NSFVWTlVpQkVhWEpsWTNRZ1ZHVnpkQ0JFWlhacFkyVWdVM1ZpUTBFeE1CNFhEVEl5TVRFd056SXhNVFEwTkZvWERUSXpNVEV3TnpJeE1UUTBORm93ZkRFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01Da05oYkdsbWIzSnVhV0V4SFRBYkJnTlZCQW9NRkVobFlXeDBhQ0JIYjNKcGJHeGhMQ0JKYm1NdU1SVXdFd1lEVlFRTERBeFRSVkZWVDBsQkxWUkZVMVF4SWpBZ0JnTlZCQU1NR1hGaExYRm9hVzR1YUdWaGJIUm9aMjl5YVd4c1lTNWpiMjB3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRREFqam52SWNESXZXcmw0OWhrQnVSWTZtSThac2R1dFI5c2FjcmorNCtCK043T2N4WGpmWXR3T3FheTYxaVByUWpEN0thck9VMEZmbHBPNGZBYTQ5WGJuTlpJSFhVNW5FL0tzaEU0YVplQzhOM2tvV1MxZUlxbFNsbnE2S2lGS1RVaVRLZmw4cVRWS1lnTFBiSmE4dGgzaXRGWTdvMGlUSDRIQlNSNCtBeEZtWDltdVJKVnI1MEpydW5LL2RWdGEwTTVFY200cmJDR1hoY3pXRGhnenFtNG8vN20rbE41emZoRm1rVEVFakcwZkM1ZmVrdHZlS1RVYjJGREFiVzR0aXFJVDJKWStpTlpZZU9rZEo4V3dBeXZtMzVOSlZ4eWQ1dyt6OUhCUTc1MUJwWk1qNkhOMXptTGlqVElCdXU5VjV0NXRMbjRUNUF0NzFlbXJuVk1SQzk5QWdNQkFBR2pnZ0ZTTUlJQlRqQmFCZ2dyQmdFRkJRY0JBUVJPTUV3d1NnWUlLd1lCQlFVSE1BS0dQbWgwZEhBNkx5OWpaWEowY3k1bGJYSmthWEpsWTNRdVkyOXRMMk5sY25SekwwVk5Va1JwY21WamRGUmxjM1JFWlhacFkyVlRkV0pEUVRFdVkzSjBNQjBHQTFVZERnUVdCQlRLQXNjSkZYNUtxWUphSDRIai9VV0FlaFhmRERBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRlBHbVBpYWVKVUJzRENXbXVBWVVXaGM4cVJ6ZU1FMEdBMVVkSHdSR01FUXdRcUJBb0Q2R1BHaDBkSEE2THk5alpYSjBjeTVsYlhKa2FYSmxZM1F1WTI5dEwyTnliQzlGVFZKRWFYSmxZM1JVWlhOMFJHVjJhV05sVTNWaVEwRXhMbU55YkRBT0JnTlZIUThCQWY4RUJBTUNCYUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01DUUdBMVVkRVFRZE1CdUNHWEZoTFhGb2FXNHVhR1ZoYkhSb1oyOXlhV3hzWVM1amIyMHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQUo3SitKSmErTTllUVNRYk0zaGNWRVhOblQxWnYyaGdvQU5CVEJkRGtQYXJBQUUxWitidkc3WmsyQUMzZmpSOXFIQ1JFWFFJOFJrNlVjekVLNjBFYXJZeWk3YmI1clhIVzNBVDYrVTZ0RER1UnFXSDVmRzhPM1ViMTA4VEIvdlFBdEFQQzZXY1VUK3ROa0VPL2lQSUl2UHR4NGxSMlhQWUl1YUlXN016aXRMTGxiM2FPKzN0WjVjVC9uaHplZWc1WmxyVWZDNjhub0NiN09UK2graFRkbEJTYlVSVllSK1ZGVG1YZFpWQWx1UDhlNWkvQkd2M2U0cHlXbTcyUDFxRXkrTXU0SDM0Y3Njb3Ixd1JmR3ltWFN2TW1zbytkTmR3QVg1cGxPS2diaU9SUTZyTktLSitRZnhIR3AvWEdOcVg5c09nS2pTNldvdWFIMnN1bjV2L1pvPSIsIk1JSUZ1ekNDQTZPZ0F3SUJBZ0lJRXpveHphaEY1cG93RFFZSktvWklodmNOQVFFTEJRQXdnWmd4Q3pBSkJnTlZCQVlUQWxWVE1Rc3dDUVlEVlFRSUV3SkRRVEVTTUJBR0ExVUVCeE1KVTJGdUlFUnBaV2R2TVJNd0VRWURWUVFLRXdwRlRWSWdSR2x5WldOME1UWXdOQVlEVlFRTEV5MURaWEowYVdacFkyRjBhVzl1SUVGMWRHaHZjbWwwZVNBb1kyVnlkSE11WlcxeVpHbHlaV04wTG1OdmJTa3hHekFaQmdOVkJBTVRFa1ZOVWlCRWFYSmxZM1FnVkdWemRDQkRRVEFlRncweE5EQXpNREV3TkRFeU1EaGFGdzB5TkRBeU1qa3dOREV5TURoYU1JR2pNUXN3Q1FZRFZRUUdFd0pWVXpFTE1Ba0dBMVVFQ0F3Q1EwRXhFakFRQmdOVkJBY01DVk5oYmlCRWFXVm5iekVUTUJFR0ExVUVDZ3dLUlUxU0lFUnBjbVZqZERFMk1EUUdBMVVFQ3d3dFEyVnlkR2xtYVdOaGRHbHZiaUJCZFhSb2IzSnBkSGtnS0dObGNuUnpMbVZ0Y21ScGNtVmpkQzVqYjIwcE1TWXdKQVlEVlFRRERCMUZUVklnUkdseVpXTjBJRlJsYzNRZ1JHVjJhV05sSUZOMVlrTkJNVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFJWjhpbHVRR0U4akVtcE03bFRBT2thMkEvL1djUEVOMlNSNGV6SlZTVmNZaUg1MWpzYWt1WGFoSGR1OEtMS1JSdjUzTlowTjd6aXlRMURrWnByeUZYalV0SXBxYlNqbnRZN2ZaWW9DOWhvWFhpUmJ1YnZ4SVhwU0wvUUpkZmFYNkVoMDZHZ28zYUhBS0o4Y2R1UWNSRW5EY05Mb25MbWVLOHM2VkMraTE3c1A2VWZZQm5OajBuVkdQcFpGd1gxamtXL1dTcnE2VDJRaktwOXloelgvQ0xYY3pxQTc2dGpTUm1LNEhNQVEyak9qdmgvbWZldHkrTTY4WC8wMTFMclpRRWxxNzk3T2VPdXk3WFVMNmxVYjR2eG9TQXNFMmJMeUxlL2pMcEw1V1VTUGF6YlUva3BRYk55bGhJdDh6cmJrc21UM1ArRTd0VmU2Um0xQWpyWmtldU1DQXdFQUFhT0IrekNCK0RCUUJnZ3JCZ0VGQlFjQkFRUkVNRUl3UUFZSUt3WUJCUVVITUFLR05HaDBkSEE2THk5alpYSjBjeTVsYlhKa2FYSmxZM1F1WTI5dEwyTmxjblJ6TDBWTlVrUnBjbVZqZEZSbGMzUkRRUzVqY25Rd0hRWURWUjBPQkJZRUZQR21QaWFlSlVCc0RDV211QVlVV2hjOHFSemVNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdId1lEVlIwakJCZ3dGb0FVTWRhRUwwbVliZ0FCMEdlaCtKNGNzRytub3F3d1F3WURWUjBmQkR3d09qQTRvRGFnTklZeWFIUjBjRG92TDJObGNuUnpMbVZ0Y21ScGNtVmpkQzVqYjIwdlkzSnNMMFZOVWtScGNtVmpkRlJsYzNSRFFTNWpjbXd3RGdZRFZSMFBBUUgvQkFRREFnR0dNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUNBUUFBY2d2REtnNzBDbFh2TzNTbmZJeVhmSm5pZjBkNlZoZEZ0VG9OUnBKU21XVkd2eGhhVXZhaVlOWW1uUWJTelliWXJHSFcyYWlVUXI0MUtsWUFhVWtQVUZ4VTE3L1RpUXlqNXVsK3plaWNKYUJxSndXN2dhTDVjR1g1VzhOVHhwYXBiYVo2T2haQTlNSy81bFNETVMvQ2c0MlEycW9HTEZxWkRDVkUvRkZPM3l0Q1VDejRmMkdMblVkVTdiOGRsMHF5d0tQc3JpalVicDdFcUt6cUwzYk02YVFuMjhyTkU2SUYycGZvaXlrblk2S2lDY2JyTzFDWUs5eHBUSktJdlZ5ZHN4em5wc240TUVFeWNrcGQwRS9iekFhd01LSW5wZmp1TW5qdWRzcHM3YUxreHJvSlJubVJ4QlRSdnoxb2JURDJYNUFBSmo4VkZaTUMvOGdodGFVS2lsVVdHVkVtTEh1ZHd2VG9LUUJDcnNJSnY5bTZCRkdDLzZ1M1YvNjFwTTFpRzkvRUdzTVBnS0xKUmtXdyt3YnNwTGpzT0Zjdm01Mmp5WUUrRVVxMU9hMFp4QmVlVTFPZmlDaHFwWnlMdFMydy9jd0JHSjVOQUtUczcvUWx3NDUyT3VPSnhiVThsMVNrUnU5anZQa3QzdS9qL1lLVE9JSWh3MTZENDViOUNkcTJEMVl5SlJydTVLeHhTeGd0QURSejVDb0YxSnVnOGw3Zm9kdzJaL0h0c2lBNGFCcGJCMW4wWXZtSFhMRFRPZE5yaW1BclFhWCtUT3hVZjRta29TNENtNVEydXM1aUk5WGV2amJrSk4wd2FGTnRBc3I4TzRNYUlRN3B2cWVvZkdZU29PR3F1blVlRmZpeUUvU3NWNzVBbnJTd2s5WFFIcHFmYnVzODROczhaQT09IiwiTUlJR1pqQ0NCRTZnQXdJQkFnSUJBVEFOQmdrcWhraUc5dzBCQVFzRkFEQ0JtREVMTUFrR0ExVUVCaE1DVlZNeEN6QUpCZ05WQkFnVEFrTkJNUkl3RUFZRFZRUUhFd2xUWVc0Z1JHbGxaMjh4RXpBUkJnTlZCQW9UQ2tWTlVpQkVhWEpsWTNReE5qQTBCZ05WQkFzVExVTmxjblJwWm1sallYUnBiMjRnUVhWMGFHOXlhWFI1SUNoalpYSjBjeTVsYlhKa2FYSmxZM1F1WTI5dEtURWJNQmtHQTFVRUF4TVNSVTFTSUVScGNtVmpkQ0JVWlhOMElFTkJNQjRYRFRFeU1Ea3dOakEwTXpFek5sb1hEVE15TURrd05qQTBNekV6Tmxvd2daZ3hDekFKQmdOVkJBWVRBbFZUTVFzd0NRWURWUVFJRXdKRFFURVNNQkFHQTFVRUJ4TUpVMkZ1SUVScFpXZHZNUk13RVFZRFZRUUtFd3BGVFZJZ1JHbHlaV04wTVRZd05BWURWUVFMRXkxRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlU0FvWTJWeWRITXVaVzF5WkdseVpXTjBMbU52YlNreEd6QVpCZ05WQkFNVEVrVk5VaUJFYVhKbFkzUWdWR1Z6ZENCRFFUQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQUx1Z2s1Nkhvb3Q2eUVFb2hiUlFkUVA2c01UQ3pYT1NneEhyZVlJNGgwMEVoTWI4eDhWekQvWkNFZGdtcndhNnkxV0U3V2FQZFRjWC9qQ2QwR05Vd2dxUHo3c0xQMk5lVEE5a2duL20wa1h2eElnemFFaEpudGRxZHZ6SHFsaHRJTUFVUkF1OWVyQWZNbjBnaUs3end0U2c1Yll3QzA5dHl2NGRSSUFYOVV1dk9wT3FKblFrOURSUmQ2NCs5RUtrWDlaajFscVQwL1dqcjB3M2pjR1lOMDJkQjAzVDRXQVJaRXVnemtCelBjbVlQTGhsMDlnUnJnUWc4bXNnVFFpNjh2UitVS05Vb1FoUkpBa2svQ0Fxa01UOFV6dWFlL1c3dXRZazQvdm1pSkVIb0M3T1Y3eUdhN1ZyRDBIaGpEemZzNTNrZG5uemxvNk1CKzZvR0Z0SUthTUY0RDhHVlNyK01ZL3BhK0MyZGtxZjR5M1ByM2hxTTN0NHZnbXIvZWcwZGh6aDkrejRscEVaejljaVdjT1h3am14ZWMzT0ZhbnZNT2VHNE9oS1JpR0lqL21Wa0RFV2xDM3RjZFAyMkR0R2svUkhHT0pIa2Y2cUtGeGVORE9GSFVkVHBpWGxkQWwzY1VnOUJOQWxVbldIRndpbStieXh4Vll6bVhzLzhLZkxmT3A2eElGakkvZWRkTkU3L2F2UVdvRWtPYXBnVURmYWl4V2lJMWQ0MFFHS0pyMGQxWW8rVzVWeHp6dWZKcDVpQy80RW1sWXphSzkrZFZPdGZRR2ZOV2FYbWZZYThIN2tyY3JXY3ZwMGFuZG80UmVoM2ErcXB5YnZCVnlSSnJlZTFXT0RRSHFzN0oybHg5cXV5VmZJM0JveDN1Yy9IdzJ4eGRqeFYzY1VzdmQ1QWdNQkFBR2pnYmd3Z2JVd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBT0JnTlZIUThCQWY4RUJBTUNBUVl3SFFZRFZSME9CQllFRkRIV2hDOUptRzRBQWRCbm9maWVITEJ2cDZLc01COEdBMVVkSXdRWU1CYUFGREhXaEM5Sm1HNEFBZEJub2ZpZUhMQnZwNktzTUQ4R0ExVWRId1E0TURZd05LQXlvRENHTG1oMGRIQTZMeTlqWlhKMGN5NWxiWEprYVhKbFkzUXVZMjl0TDBWTlVrUnBjbVZqZEZSbGMzUkRRUzVqY213d0VRWURWUjBnQkFvd0NEQUdCZ1JWSFNBQU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQ0FRQnNYYlk4QjdGY0lza3llQi9DR0VJNzdHYURNRGZLV0dzZUpKWWxKWXoyRmVJSmdQdHFkUGh6bjBqaFFVVmN3ci8vZ0M1ajFhQVJsdXNzRzNnTXI4T2FqcFNwT3FxZlhFanp1SVRlcStIeHNwK3Vyc2lKWE9aS2h1clk1TkpLWjMwdWxGRHhPWjk3YldWVVlQVGZ5eTFxVXJzcW5ObFc4TEpjQ25OeloydURTSm4zMkZ1Z1V0V2UwRUVnUk0xMC84UTJJSlhMdUloRVFMYndsNnE3UGNEaVBrVC95VmgvOUw2dWwyYk8vWlhwN0RlU1BlT2FmV091Q29UTmJLeGdCdWxqYWptMlZOQjUrWHgvclN1UG5vVFJoc2FYaGtlK25iM1piR0hKMlpSdS9RNDUrT0Ixd3M3VmVkbk1jaTI1T1ZvK3lWcEg4dGwyS0Y5dTFKVk50ZjVtWTMvL0hFd1I4T2ZQUFJaZVFDcXF1RVNWclFqWklMYTZPdDdsVklob05JNnprWkFwM1RhV1lCaTk0dXBWa2VBOXVxVklDN2NCcGlPeis2WFhSRGRKRE11aDZ4c0EydHEyRTVCWTUxSDVwZnNrWEJCR2dIeERRNTZSM1Jza1o3cS9OYUtTaXFCQUludWVHN1RWVytkUisrclQybjl3a3pKSEtwQStZUzB6SG9kdklvQjcxS05xMVAvOWNob0NNY0JyTnBoNW4zMkM4RHBPbEYraGkza09rd2p3Y2hma3pDNVhTK1ppbzVWWU95Q1YxQytDWUo3c3cxcHNrMXlZQVdQbTlyblVtZnJtTzI3SFh2NmxXMFo5RXBlVXUrKzUyQ1NZalpzeDNFNEoxRlIwVHVsenNEOEJRdEZSTDZhUGZ1U2c4NW9rT3N4d2IvcDBBZElUeFJPMHZRPT0iXX0.eyJpc3MiOiJxYS1xaGluLmhlYWx0aGdvcmlsbGEuY29tIiwic3ViIjoicWEtcWhpbi5oZWFsdGhnb3JpbGxhLmNvbSIsImF1ZCI6Imh0dHBzOi8vc2VjdXJlZGNvbnRyb2xzLm5ldC9jb25uZWN0L3JlZ2lzdGVyIiwiZXhwIjoxNjc4NDg2MDU5LCJpYXQiOjE2Nzg0ODU3NTksImp0aSI6IjEiLCJjbGllbnRfbmFtZSI6IkhlYWx0aEdvcmlsbGEiLCJncmFudF90eXBlcyI6WyJjbGllbnRfY3JlZGVudGlhbHMiXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2QiOiJwcml2YXRlX2tleV9qd3QiLCJzY29wZSI6InN5c3RlbS8qLiogb2ZmbGluZV9hY2Nlc3MifQ.UhLRP4Lpd4yGliMz5w66rXYh_RULP03HcE3Qyk2LpQ76HOp8KlU6rdxt5JhviELu4DkUmWf7gAWfm5O4x1iF96YXo-VOQ-6OwUZ4CiTU6H5IZsSCsXeF9hkpz7bPdIA8TPW55WaDBvqBnf5eQy5EJrPvTD5xRE2EraP7yPHfjeY_wL0fH9cYjb9up1rfuST9V-_CkRT286QcZKLmkVKqFdb5AZmRi_pZQryZYamnmLHkeN0f7Epl7uuAonox9MuZvlMG6Ca-IIudR7JGBppTNA-iFmICA2wSkhC03rLmX92enPc8oBjRZlQRGxyJE4hHAa-AVAsvuWGzUkSuTDw80A"", ""certifications"": [], ""udap"": ""1""}";

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
