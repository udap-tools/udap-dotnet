#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;
public class AuthorizationCodeRequest
{
    public string? ResponseType { get; set; }
    public string? State { get; set; }

    public string? ClientId { get; set; }

    public string? Scope { get; set; }

    public string? RedirectUri { get; set; }
    public string? Aud { get; set; }
    public string? IdPBaseUrl { get; set; }
}
