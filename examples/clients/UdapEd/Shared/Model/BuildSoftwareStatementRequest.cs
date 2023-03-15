#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Model.Registration;

namespace UdapEd.Shared.Model;
public class BuildSoftwareStatementRequest
{
    public string? MetadataUrl { get; set; }

    public string? Audience { get; set; }

    public Oauth2FlowEnum Oauth2Flow { get; set; }

    public string? RedirectUri { get; set; }

    public string? Scope { get; set; }
}

public class RawSoftwareStatementAndHeader
{
    public string Header { get; set; } = string.Empty;

    public string SoftwareStatement { get; set; } = string.Empty;

    public string? Scope { get; set; } = string.Empty;
}

public class RegistrationRequest
{
    public string? RegistrationEndpoint { get; set; }
    public UdapRegisterRequest? UdapRegisterRequest { get; set; }

}
