#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Validation;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Udap.Server.Extensions;

namespace Udap.Server.Services.Default;

public class DefaultScopeService: IScopeService
{
    /// <summary>
    /// UDAP does not post scopes during Access Token requests.  Rather during dynamic client
    /// registration it requests scopes.  So we must inject the scopes into the <see cref="IFormCollection"/>
    /// so the subsequent call to the <see cref="ITokenRequestValidator"/> implementation in <see cref="Duende.IdentityServer.Endpoints.TokenEndpoint"/>
    /// will not fail for missing scopes.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="client"></param>
    /// <returns></returns>
    public async Task Resolve(HttpContext context, Duende.IdentityServer.Models.Client client)
    {
        if (client.ClientSecrets.All(s => 
                s.Type == UdapServerConstants.SecretTypes.Udapx5c ||
                s.Type == UdapServerConstants.SecretTypes.Udap_X509_Pem))
        {
            var form = (await context.Request.ReadFormAsync()).AsNameValueCollection();
            form.Set(OidcConstants.TokenRequest.Scope, client.AllowedScopes.ToSpaceSeparatedString());
            var values = new Dictionary<string, StringValues>();
            foreach (var key in form.AllKeys)
            {
                values.Add(key, form.Get(key));
            }

            var formCol = new FormCollection(values);
            context.Request.Form = formCol;
        }
    }
}
