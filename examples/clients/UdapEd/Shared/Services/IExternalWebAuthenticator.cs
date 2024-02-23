#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Maui.Authentication;

namespace UdapEd.Shared.Services;
public interface IExternalWebAuthenticator
{
    Task<WebAuthenticatorResult> AuthenticateAsync(string url, string callbackUrl);
}
