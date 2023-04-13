#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Client.Authentication;
using UdapEd.Shared;

namespace UdapEd.Server.Authentication;

public class AccessTokenProvider : IAccessTokenProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AccessTokenProvider(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Task<string?> GetAccessToken(CancellationToken token = default)
    {
        var accessToken = _httpContextAccessor.HttpContext?.Session.GetString(UdapEdConstants.TOKEN);

        return Task.FromResult(accessToken);
    }
}