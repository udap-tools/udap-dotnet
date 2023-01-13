using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;
using System.Text.Json;
using IdentityModel;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using UdapClient.Client.Services;

namespace UdapClient.Client.Pages;

public partial class UdapRegistration
{
    [Inject] private HttpClient _http { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }
    [Inject] UdapClientState UdapClientState { get; set; } = new UdapClientState();
    [Inject] MetadataService MetadataService { get; set; }

    private string SoftwareStatementBeforeEncoding { get; set; } = "";
    private string RequestBody { get; set; }

    private async Task Build()
    {
        try
        {
            var now = DateTime.UtcNow;
            var jwtId = CryptoRandom.CreateUniqueId();

            var clientCert = new X509Certificate2(UdapClientState.ClientCert);
            var securityKey = new X509SecurityKey(clientCert);
            var signingCredentials = new SigningCredentials(securityKey, UdapConstants.SupportedAlgorithm.RS256);

            var certBase64 = Convert.ToBase64String(clientCert.Export(X509ContentType.Cert));
            var jwtHeader = new JwtHeader
            {
                { "alg", signingCredentials.Algorithm },
                { "x5c", new[] { certBase64 } }
            };

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

            var encodedHeader = jwtHeader.Base64UrlEncode();
            var encodedPayload = document.Base64UrlEncode();
            var encodedSignature =
                JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                    signingCredentials);
            var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
            
            var tokenHandler = new JsonWebTokenHandler();
            var jsonToken = tokenHandler.ReadToken(signedSoftwareStatement);
            var requestToken = jsonToken as JsonWebToken;

            var sb = new StringBuilder();
            sb.Append("[");
            sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedHeader));
            sb.Append(",");
            sb.Append(Base64UrlEncoder.Decode(requestToken.EncodedPayload));
            sb.Append("]");

            SoftwareStatementBeforeEncoding = JsonObject.Parse(sb?.ToString())
                .ToJsonString(new JsonSerializerOptions()
                {
                    WriteIndented = true, 
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                });
        }
        catch (Exception ex)
        {
            SoftwareStatementBeforeEncoding = ex.Message;
        }
    }

    private void BuildRequestBody()
    {
        RequestBody = string.Empty;
    }

    

    private async Task UploadFilesAsync(InputFileChangeEventArgs e)
    {
        long maxFileSize = 1024 * 10;

        var uploadStream = await new StreamContent(e.File.OpenReadStream(maxFileSize)).ReadAsStreamAsync();
        var ms = new MemoryStream();
        await uploadStream.CopyToAsync(ms);
        var certBytes = ms.ToArray();

        await MetadataService.UploadClientCert(Convert.ToBase64String(certBytes));
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }

    
}
