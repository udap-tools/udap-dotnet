#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Utility;
using Udap.Client.Rest;
using UdapEd.Shared;

namespace UdapEd.Server.Rest;

public class BaseUrlProvider : IBaseUrlProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public BaseUrlProvider(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    
    public Uri GetBaseUrl()
    {
        var baseUrl = _httpContextAccessor.HttpContext?.Session.GetString(UdapEdConstants.BASE_URL);
        
        return new Uri(baseUrl.EnsureEndsWith("/"));
    }
}
