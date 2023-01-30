#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion


namespace UdapClient.Shared.Model;
public class AccessTokenRequestModel
{
    public string ClientId { get; set; }
    public string Password { get; set; }
    public string TokenEndpointUrl { get; set; }
}
