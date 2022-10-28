#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Registration;

public class UdapDynamicClientRegistrationValidationResult
{
    public UdapDynamicClientRegistrationValidationResult(
        Duende.IdentityServer.Models.Client client, 
        UdapDynamicClientRegistrationDocument document)
    {
        ArgumentNullException.ThrowIfNull(client);

        Client = client;
        Document = document;
    }

    public UdapDynamicClientRegistrationValidationResult(string error, string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(errorDescription);

        Error = error;
        ErrorDescription = errorDescription;
    }
    
    public Duende.IdentityServer.Models.Client? Client { get; }

    public UdapDynamicClientRegistrationDocument Document;

    public string? Error { get; }
    
    public string? ErrorDescription { get; }

    public bool IsError => !string.IsNullOrWhiteSpace(Error);
}