#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security;
using Udap.Model.Registration;

namespace UdapClient.Shared.Model;
public class BuildSoftwareStatementRequest
{
    public string MetadataUrl { get; set; }

    public string Password { get; set; }
    public string? Audience { get; set; }
}

public class RegistrationRequest
{
    public string RegistrationEndpoint { get; set; }
    public UdapRegisterRequest UdapRegisterRequest { get; set; }

}
