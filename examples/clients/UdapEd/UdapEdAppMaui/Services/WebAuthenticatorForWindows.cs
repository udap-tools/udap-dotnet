#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

#if WINDOWS
using AutoMapper;
using UdapEd.Shared.Services;

namespace UdapEdAppMaui.Services;
public class WebAuthenticatorForWindows : IExternalWebAuthenticator
{
    public async Task<WebAuthenticatorResult> AuthenticateAsync(string url, string callbackUrl)
    {
        var result = await WinUIEx.WebAuthenticator.AuthenticateAsync(
            new Uri(url),
            new Uri(callbackUrl));

        return result.Map();
    }
}

public static class WebAuthenticatorResultMapper
{
    static WebAuthenticatorResultMapper()
    {
        Mapper = new MapperConfiguration(cfg =>
            {
                cfg.AddProfile<WebAuthenticatorResultProfile>();
            })
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps a <see cref="WinUIEx.WebAuthenticatorResult"/> to a <see cref="WebAuthenticatorResult"/>.
    /// </summary>
    /// <param name="request">The WebAuthenticatorResult.</param>
    /// <returns></returns>
    public static WebAuthenticatorResult Map(this WinUIEx.WebAuthenticatorResult request)
    {
        return Mapper.Map<WebAuthenticatorResult>(request);
    }
}

public class WebAuthenticatorResultProfile : Profile
{
    public WebAuthenticatorResultProfile()
    {
        CreateMap<WinUIEx.WebAuthenticatorResult, WebAuthenticatorResult>();
    }
}

#endif