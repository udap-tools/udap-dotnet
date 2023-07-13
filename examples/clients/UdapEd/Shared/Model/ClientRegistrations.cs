#region (c) 2023 Joseph Shook. All rights reserved.

// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */

#endregion

namespace UdapEd.Shared.Model;

public class ClientRegistrations
{
    public ClientRegistrations()
    {

    }

    public ClientRegistration? SelectedRegistration { get; set; } 

    public Dictionary<string, ClientRegistration> Registrations { get; set; } = new();

    public void SetRegistration(RegistrationDocument? resultModelResult, Oauth2FlowEnum oauth2Flow, string resourceServer)
    {
        if (resultModelResult is { ClientId: not null, Issuer: not null, Audience: not null })
        {
            Registrations[resultModelResult.ClientId] = new ClientRegistration
            {
                ClientId = resultModelResult.ClientId,
                GrantType = resultModelResult.GrantTypes.FirstOrDefault(),
                SubjAltName = resultModelResult.Issuer,
                UserFlowSelected = oauth2Flow.ToString(),
                AuthServer = resultModelResult.Audience,
                ResourceServer = resourceServer,
                RedirectUri = resultModelResult.RedirectUris.FirstOrDefault(),
                Scope = resultModelResult.Scope
            };
        }
    }

    public void CancelRegistration(RegistrationDocument? resultModelResult)
    {
        if (resultModelResult != null)
        {
            var clients = Registrations.Where(r =>
                    resultModelResult.Issuer == r.Value.SubjAltName &&
                    resultModelResult.Audience == r.Value.AuthServer)
                .ToList();

            foreach (var client in clients)
            {
                Registrations.Remove(client.Key);
            }
        }
    }
}

public class ClientRegistration
{
    public string ClientId { get; set; } = string.Empty;
    public string UserFlowSelected { get; set; } = string.Empty;
    public string? GrantType { get; set; } = string.Empty;
    public string SubjAltName { get; set; } = string.Empty;
    public string AuthServer { get; set; } = string.Empty;
    public string ResourceServer { get; set; } = string.Empty;
    public string? RedirectUri { get; set; }
    public string? Scope { get; set; }
}