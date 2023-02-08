#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Models;

namespace Udap.Server.Storage.Stores;

/// <summary>
/// UDAP store used retrieving configuration data
/// </summary>
public interface IUdapClientConfigurationStore
{
    Task<Duende.IdentityServer.Models.Client?> GetClient(Duende.IdentityServer.Models.Client client, CancellationToken token = default);

    Task<IEnumerable<Anchor>> GetAnchors(CancellationToken token = default);
}