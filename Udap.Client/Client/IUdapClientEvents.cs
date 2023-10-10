#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;

namespace Udap.Client.Client;

public interface IUdapClientEvents
{
    /// <summary>
    /// Event fired when a certificate is untrusted
    /// </summary>
    event Action<X509Certificate2>? Untrusted;

    /// <summary>
    /// Event fired if a certificate has a problem.
    /// </summary>
    event Action<X509ChainElement>? Problem;

    /// <summary>
    /// Event fired if there was an error during certificate validation
    /// </summary>
    event Action<X509Certificate2, Exception>? Error;

    /// <summary>
    /// Event fired when JWT Token validation fails
    /// </summary>
    event Action<string>? TokenError;
}