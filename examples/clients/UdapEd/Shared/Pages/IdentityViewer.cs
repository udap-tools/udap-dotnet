using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.IdentityModel.Tokens;

namespace UdapEd.Shared.Pages;

public partial class IdentityViewer
{

    [Parameter]
    public string? IdentityToken { get; set; }

    [Parameter]
    public string? Title { get; set; }

    public string? DecodedJwt => _decodedJwt;
    private string? _decodedJwt;

    /// <summary>
    /// Method invoked when the component has received parameters from its parent in
    /// the render tree, and the incoming values have been assigned to properties.
    /// </summary>
    /// <returns>A <see cref="T:System.Threading.Tasks.Task" /> representing any asynchronous operation.</returns>
    protected override async Task OnParametersSetAsync()
    {
        DecodeIdentityToken();
        await base.OnParametersSetAsync();
    }

    private void DecodeIdentityToken()
    {
        if (IdentityToken == null)
        {
            _decodedJwt = string.Empty;
            return;
        }

        try
        {
            var jwt = new JwtSecurityToken(IdentityToken);
            using var jsonDocument = JsonDocument.Parse(jwt.Payload.SerializeToJson());
            var formattedStatement = JsonSerializer.Serialize(
                jsonDocument,
                new JsonSerializerOptions { WriteIndented = true }
            );

            var formattedHeader = UdapEd.Shared.JsonExtensions.FormatJson(Base64UrlEncoder.Decode(jwt.EncodedHeader));

            var sb = new StringBuilder();
            sb.AppendLine("<p class=\"text-line\">HEADER: <span>Algorithm & TOKEN TYPE</span></p>");

            sb.AppendLine(formattedHeader);
            sb.AppendLine("<p class=\"text-line\">PAYLOAD: <span>DATA</span></p>");
            sb.AppendLine(formattedStatement);

            _decodedJwt = sb.ToString();
        }
        catch (Exception ex)
        {
            _decodedJwt = ex.Message;
        }
    }
}
