#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;
public class LoginCallBackResult
{
    public string? Code { get; set; }

    public string? Scope { get; set; }
   
    public string? State { get; set; }

    public string? SessionState { get; set; }

    public string? Issuer { get; set; }
}
