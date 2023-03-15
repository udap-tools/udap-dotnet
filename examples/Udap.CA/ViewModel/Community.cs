#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.CA.ViewModel
{
    public class Community
    {
        public int Id { get; set; }

        public string Name { get; set; } = string.Empty;

        public bool Enabled { get; set; }

        public ICollection<RootCertificate> RootCertificates { get; set; } = new HashSet<RootCertificate>();
        
        public bool ShowRootCertificates { get; set; }
    }
}
