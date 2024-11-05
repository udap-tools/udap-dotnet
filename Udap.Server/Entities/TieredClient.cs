#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// ReSharper disable PropertyCanBeMadeInitOnly.Global
namespace Udap.Server.Entities;

public class TieredClient
{
    //TODO: do I need to retain scopes?  Or is it always a standard set of scopes?

    public int Id { get; set; }
    public string ClientName { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string IdPBaseUrl { get; set; } = default!;
    public string RedirectUri { get; set; } = default!;

    public string ClientUriSan { get; set; } = default!;

    public int CommunityId { get; set; }
    public bool Enabled { get; set; }

    public string TokenEndpoint { get; set; } = default!;

}