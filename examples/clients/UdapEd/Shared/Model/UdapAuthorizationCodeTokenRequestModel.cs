#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using IdentityModel.Client;
using Udap.Model;
using Udap.Model.Access;

namespace UdapEd.Shared.Model;

/// <summary>
/// Blazor Deserialize in wasm client could not deserialize the original
/// <see cref="UdapAuthorizationCodeTokenRequest"/> when running the "Published"
/// application.  Yet in all other builds, debug, release etc it deserialization
/// worked correctly.
/// </summary>
public class UdapAuthorizationCodeTokenRequestModel : UdapBaseTokenRequestModel
{
    public string Udap { get; set; } = UdapConstants.UdapVersionsSupportedValue;

    public string? GrantType { get; set; }

    public string? Code { get; set; }

    public string? RedirectUri { get; set; }

    public UdapAuthorizationCodeTokenRequest ToUdapAuthorizationCodeTokenRequest()
    {
        ArgumentNullException.ThrowIfNull(Version);

        var request = new UdapAuthorizationCodeTokenRequest()
        {
            RequestUri = RequestUri,
            Version = Version,
            // Method = Method,
            Code = Code,
            RedirectUri = RedirectUri,
            Address = Address,
            AuthorizationHeaderStyle = AuthorizationHeaderStyle,
            ClientAssertion = new ClientAssertion { Type = ClientAssertion?.Type, Value = ClientAssertion?.Value },
            ClientCredentialStyle = ClientCredentialStyle,
            ClientId = ClientId,
            ClientSecret = ClientSecret,
            Parameters = new Parameters()
        };

        foreach (var item in Resource) Resource.Add(item);

        foreach (var item in Parameters) request.Parameters.Add(item);

        // clone.Headers.Clear();
        // foreach (var header in Headers)
        // {
        //     clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        // }

        return request;
    }
}