#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Extensions;

namespace Udap.Common.Models;

public class Anchor
{
    public Anchor(){}
    public Anchor(X509Certificate2 cert)
    {
        Certificate = cert.ToPemFormat();
        BeginDate = cert.NotBefore;
        EndDate = cert.NotAfter;
    }
    public long Id { get; set; }
    public bool Enabled { get; set; }
    public string Name { get; set; }
    public string Community { get; set; }
    public long CommunityId { get; set; }
    public string Certificate { get; set; }
    public string Thumbprint { get; set; }
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }
}