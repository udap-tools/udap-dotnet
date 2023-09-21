#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;

public class ClientHeaders
{
    public List<ClientHeader>? Headers { get; set; }
}


public class ClientHeader
{
    public string Name { get; set; }

    public string Value { get; set; }
}

