#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;
public class ClientStatus
{
    public ClientStatus(bool isValid, string statusMessage)
    {
        IsValid = isValid;
        StatusMessage = statusMessage;
    }

    public bool IsValid { get; set; }

    public string StatusMessage { get; set; }
}

