#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security;
using System.Security.Cryptography.X509Certificates;
using Udap.Model;
using Udap.Model.Registration;

namespace UdapClient.Client.Services;

public class UdapClientState
{
    public UdapClientState() {}

    public string MetadataUrl { get; set; } = "https://fhirlabs.net/fhir/r4/.well-known/udap";

    public UdapMetadata? UdapMetadata { get; set; }
    
    public string SoftwareStatementBeforeEncoding { get; set; }

    public UdapRegisterRequest? RegistrationRequest { get; set; }

    /// <summary>
    /// Result from dynamic client registration
    /// </summary>
    public UdapDynamicClientRegistrationDocument AccessCode { get; set; }

    private bool _isLocalStorageInit;

    public bool IsLocalStorageInit()
    {
        return _isLocalStorageInit;
    }

    public void LocalStorageInit()
    {
        _isLocalStorageInit = true;
    }
}

