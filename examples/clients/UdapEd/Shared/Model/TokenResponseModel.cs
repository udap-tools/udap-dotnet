#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;
public class TokenResponseModel
{
    public bool IsError { get; set; }

    public string? Error { get; set; }

    public string? AccessToken { get; set; }

    public string? IdentityToken { get; set; }

    public string? RefreshToken { get; set; }

    public DateTime ExpiresAt { get; set; }

    public string? Scope { get; set; }

    public string? TokenType { get; set; }

    public string? Raw { get; set; }

    public string? Headers { get; set; }
}
