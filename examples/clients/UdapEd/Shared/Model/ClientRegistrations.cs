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

public class ClientRegistrations
{
    private ClientRegistration? _clientRegistration;

    public ClientRegistration? SelectedRegistration { get; set; } 

    public Dictionary<string, ClientRegistration?> Registrations { get; set; } = new();

    public ClientRegistration? SetRegistration(RegistrationDocument registrationDocument, UdapDynamicClientRegistrationDocument? resultModelResult, Oauth2FlowEnum oauth2Flow, string resourceServer)
    {
        if (resultModelResult is { Issuer: not null, Audience: not null })
        {
            _clientRegistration = new ClientRegistration
            {
                ClientId = registrationDocument.ClientId,
                GrantType = resultModelResult.GrantTypes?.FirstOrDefault(),
                SubjAltName = resultModelResult.Issuer,
                UserFlowSelected = oauth2Flow.ToString(),
                AuthServer = resultModelResult.Audience,
                ResourceServer = resourceServer,
                RedirectUri = resultModelResult.RedirectUris,
                Scope = registrationDocument.Scope
            };

            Registrations[registrationDocument.ClientId] = _clientRegistration;
            CleanUpRegistration(_clientRegistration);

            return _clientRegistration;
        }

        return null;
    }

    private void CleanUpRegistration(ClientRegistration registration)
    {
        var clientId = Registrations.Where(r =>
            r.Value != null &&
            r.Value.SubjAltName == registration.SubjAltName &&
            r.Value.AuthServer == registration.AuthServer &&
            r.Value.ResourceServer == registration.ResourceServer &&
            r.Value.UserFlowSelected == registration.UserFlowSelected &&
            r.Value.ClientId != registration.ClientId)
            .Select(r => r.Key)
            .ToList();

        if (clientId.Any())
        {
            foreach (var id in clientId)
            {
                Registrations.Remove(id);
            }
        }
    }

    public void CancelRegistration(RegistrationDocument? resultModelResult)
    {
        if (resultModelResult != null)
        {
            var clients = Registrations.Where(r =>
                    r.Value != null &&
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
    public ICollection<string>? RedirectUri { get; set; }
    public string? Scope { get; set; }
    public string? IdPBaseUrl { get; set; }
}