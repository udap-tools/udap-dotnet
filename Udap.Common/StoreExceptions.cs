#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common;

public enum UdapStoreError
{
    UniqueConstraint,
}

public class DuplicateCommunityException : Exception
{
    public DuplicateCommunityException(string message) : base(message)
    {
    }
}

public class DuplicateAnchorException : Exception
{
    public DuplicateAnchorException(string message) : base(message)
    {
    }
}

public class DuplicateIntermediateCertificateException : Exception
{
    public DuplicateIntermediateCertificateException(string message) : base(message)
    {
    }
}