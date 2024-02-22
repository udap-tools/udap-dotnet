#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using UdapEd.Shared.Services;

namespace UdapEdAppMaui.Services;

public class WebAuthenticatorForDevice : IExternalWebAuthenticator
{
    public async Task<WebAuthenticatorResult> AuthenticateAsync(string url, string callbackUrl)
    {
        var result = await WebAuthenticator.Default.AuthenticateAsync(
            new Uri(url),
            new Uri(callbackUrl));

        return result;
    }
}