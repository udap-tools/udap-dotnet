#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;

public class AuthorizationCodeTokenRequestModel
{
    public string? ClientId { get; set; }
    public string? TokenEndpointUrl { get; set; }

    public string? Code { get; set; }

    public string? RedirectUrl { get; set; }

    public bool LegacyMode { get; set; } = false;
}