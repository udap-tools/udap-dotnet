#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Models;

namespace Udap.Server.Models;
public class UdapIdentityProvider : IdentityProvider
{
    public UdapIdentityProvider() : base("udap_oidc"){}

    /// <summary>
    /// Ctor
    /// </summary>
    public UdapIdentityProvider(IdentityProvider other) : base("udap_oidc", other)
    {
    }

    /// <summary>The base address of the OIDC provider.</summary>
    public string? Authority { get; set; }
    /// <summary>The response type. Defaults to "id_token".</summary>
    public string ResponseType { get; set; }
    /// <summary>The client id.</summary>
    public string? ClientId { get; set; }
    /// <summary>
    /// The client secret. By default this is the plaintext client secret and great consideration should be taken if this value is to be stored as plaintext in the store.
    /// </summary>
    public string? ClientSecret { get; set; }
    /// <summary>Space separated list of scope values.</summary>
    public string Scope { get; set; }
    /// <summary>
    /// Indicates if userinfo endpoint is to be contacted. Defaults to true.
    /// </summary>
    public bool GetClaimsFromUserInfoEndpoint { get; set; }
    /// <summary>Indicates if PKCE should be used. Defaults to true.</summary>
    public bool UsePkce { get; set; }
    /// <summary>Parses the scope into a collection.</summary>
    public IEnumerable<string> Scopes { get; }
}
