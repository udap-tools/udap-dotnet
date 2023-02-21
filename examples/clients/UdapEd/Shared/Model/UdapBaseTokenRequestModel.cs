#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using IdentityModel.Client;

namespace UdapEd.Shared.Model;

public class UdapBaseTokenRequestModel
{
    public ICollection<string> Resource { get; set; } = new HashSet<string>();

    public string? Address { get; set; }

    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    public ClientAssertionModel? ClientAssertion { get; set; }

    public ClientCredentialStyle ClientCredentialStyle { get; set; } = ClientCredentialStyle.AuthorizationHeader;

    public BasicAuthenticationHeaderStyle AuthorizationHeaderStyle { get; set; } = BasicAuthenticationHeaderStyle.Rfc6749;

    public Parameters Parameters { get; set; } = new Parameters();

    public HttpContent? Content { get; set; }

    // public HttpRequestHeaders Headers { get; }

    // public HttpMethod Method { get; set; }

    // public IDictionary<string, object>? Properties { get; }

    public Uri? RequestUri { get; set; }

    public Version? Version { get; set; }

}