#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.CA.ViewModel;

namespace Udap.CA.Services.State
{
    public class CommunityState
    {
        public Community? Community { get; set; }

        public ICollection<RootCertificate>? RootCertificates { get; set;}

        public void SetState(Community value) {
            Community = value;
        }

        public void SetState(ICollection<RootCertificate> value)
        {
            RootCertificates = value;
        }
    }
}
