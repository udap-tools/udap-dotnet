#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;

public class AccessCodeRequestResult
{
    public bool IsError { get; set; }

    public string? Message { get; set; }

    public string? RedirectUrl { get; set; }
    public IEnumerable<string>? Cookies { get; set; }
}
    
