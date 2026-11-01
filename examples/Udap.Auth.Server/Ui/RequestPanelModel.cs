#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Auth.Server.Ui;

/// <summary>What the request panel (Pages/Shared/_RequestPanel) shows: the app asking, and on what terms.</summary>
public sealed class RequestPanelModel
{
    public required string Title { get; init; }
    public string? Subtitle { get; init; }
    public IReadOnlyList<(string Label, string Value)> Facts { get; init; } = [];

    public static RequestPanelModel ForClient(Duende.IdentityServer.Models.Client? client, params (string Label, string Value)[] facts)
    {
        if (client == null)
        {
            return new RequestPanelModel { Title = "SecuredControls Auth", Subtitle = "UDAP authorization server", Facts = facts };
        }

        return new RequestPanelModel
        {
            Title = string.IsNullOrWhiteSpace(client.ClientName) ? client.ClientId : client.ClientName,
            Subtitle = Uri.TryCreate(client.ClientUri, UriKind.Absolute, out var uri) ? uri.Host : client.ClientId,
            Facts = facts
        };
    }
}
