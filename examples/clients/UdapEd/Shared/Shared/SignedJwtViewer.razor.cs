#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.IdentityModel.Tokens;
using UdapEd.Shared.Services;

namespace UdapEd.Shared.Shared;

public partial class SignedJwtViewer
{
    /// <summary>
    /// A Signed JWT
    /// </summary>
    [Parameter]
    public string? SignedSoftwareStatement { get; set; }

    [Parameter]
    public string? Title { get; set; }

    [Inject]
    public IDiscoveryService MetadataService { get; set; } = null!;

    private string? _decodedJwt;

    public string? DecodedJwt => _decodedJwt;

    /// <summary>
    /// Method invoked when the component has received parameters from its parent in
    /// the render tree, and the incoming values have been assigned to properties.
    /// </summary>
    /// <returns>A <see cref="T:System.Threading.Tasks.Task" /> representing any asynchronous operation.</returns>
    protected override async Task OnParametersSetAsync()
    {
        await BuildAccessTokenRequestVisualForClientCredentials(default);
        await base.OnParametersSetAsync();
    }

    public async Task BuildAccessTokenRequestVisualForClientCredentials(CancellationToken token)
    {
        await Task.Delay(1, token);
        if (SignedSoftwareStatement == null)
        {
            _decodedJwt = string.Empty;
            return;
        }

        var jwt = new JwtSecurityToken(SignedSoftwareStatement);
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
}
