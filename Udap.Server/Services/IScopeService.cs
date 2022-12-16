#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Http;

namespace Udap.Server.Services;

public interface IScopeService
{
    Task Resolve(HttpContext context, Duende.IdentityServer.Models.Client client);
}
