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
internal class Infrastructure : IInfrastructure
{
    public Task<string> GetMyIp()
    {
       return Task.FromResult("0.0.0.0");
    }
}
