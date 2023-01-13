using System.Security.Cryptography.X509Certificates;
using IdentityModel;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.IdentityModel.Tokens;
using MudBlazor;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Util.Extensions;
using UdapClient.Client.Services;
using UdapClient.Shared;

namespace UdapClient.Client.Pages;

public partial class UdapRegistration
{
    [Inject] private HttpClient _http { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }
    [Inject] UdapClientState UdapClientState { get; set; } = new UdapClientState();
    
    private string Result { get; set; } = "";

    private async Task Build()
    {
        try
        {
            var now = DateTime.UtcNow;
            var jwtId = CryptoRandom.CreateUniqueId();

            var document = new UdapDynamicClientRegistrationDocument
            {
                Issuer = "https://fhirlabs.net:7016/fhir/r4",
                Subject = "https://fhirlabs.net:7016/fhir/r4",
                Audience = UdapClientState.MetadataUrl,
                Expiration = EpochTime.GetIntDate(now.AddMinutes(5).ToUniversalTime()),
                IssuedAt = EpochTime.GetIntDate(now.ToUniversalTime()),
                JwtId = jwtId,
                ClientName = "udapTestClient",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" },
                GrantTypes = new HashSet<string> { "client_credentials" },
                TokenEndpointAuthMethod = UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue,
                Scope = "system/Patient.* system/Practitioner.read"
            };

            Result = document.AsJson();
        }
        catch (Exception ex)
        {
            Result = ex.Message;
        }
    }

    private async Task UploadFilesAsync(InputFileChangeEventArgs e)
    {
        long maxFileSize = 1024 * 10;

        var uploadStream = await new StreamContent(e.File.OpenReadStream(maxFileSize)).ReadAsStreamAsync();
        var ms = new MemoryStream();
        await uploadStream.CopyToAsync(ms);
        var certBytes = ms.ToArray();

        var cert = new X509Certificate2(certBytes);
        
        UdapClientState.ClientCert = cert.ToPemFormat();
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
}
