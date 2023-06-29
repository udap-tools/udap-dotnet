#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Metadata;

public class Community
{
    /// <summary>
    /// Community name as Uri
    /// </summary>
    public string Name { get; set; } = "Default";

    /// <summary>
    /// Used to map an IdP url to the client certificate when registering with the Idp
    /// </summary>
    public string? IdPBaseUrl { get; set; }

    /// <summary>
    /// Remote Idp community projection
    /// </summary>
    public string? IdpCommunityName { get; set; }

    public ICollection<string> Intermediates { get; set; } = new List<string>();

    public ICollection<AnchoFile> Anchors { get; set; } = new List<AnchoFile>();

    public ICollection<IssuedCertFile> IssuedCerts { get; set; } = new List<IssuedCertFile>();
}