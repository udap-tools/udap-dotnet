using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Text;
using Microsoft.AspNetCore.Components;
using JsonExtensions = UdapEd.Shared.JsonExtensions;

namespace UdapEd.Client.Shared;

public partial class SignedJwtViewer
{
    /// <summary>
    /// A Signed JWT
    /// </summary>
    [Parameter]
    public string? SignedSoftwareStatement { get; set; }

    [Parameter]
    public string? Title { get; set; }

    private string? DecodedJwt => BuildAccessTokenRequestVisualForClientCredentials();

    private string BuildAccessTokenRequestVisualForClientCredentials()
    {
        if (SignedSoftwareStatement == null)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        sb.AppendLine("<p class=\"text-line\">HEADER: <span>Algorithm & TOKEN TYPE</span></p>");
        var jwt = new JwtSecurityToken(SignedSoftwareStatement);
        sb.AppendLine(JsonExtensions.FormatJson(Base64UrlEncoder.Decode(jwt.EncodedHeader)));
        sb.AppendLine("<p class=\"text-line\">PAYLOAD: <span>DATA</span></p>");
        // .NET 7 Blazor Json does not deserialize complex JWT payloads like the extensions object.
        sb.AppendLine(JsonSerializer.Serialize(jwt.Payload, new JsonSerializerOptions { WriteIndented = true }));
       
        return sb.ToString();
    }
}
