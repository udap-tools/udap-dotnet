#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Client.Client
{

    public interface IUdapClient
    {
        string ClientName { get; set; }

    }

    public class UdapClient: IUdapClient
    {
        private readonly HttpClient _httpClient;

        public UdapClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }
    }
}
