#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Standard;
public static class ObjectIdentifiers
{
    public static class UdapExperimental
    {
        public static class UdapAccessControl
        {
            public static class General
            {
                public const string Create = "1.3.6.1.4.1.12345.1.1";
                public const string Read = "1.3.6.1.4.1.12345.1.2";
                public const string Update = "1.3.6.1.4.1.12345.1.3";
                public const string Delete = "1.3.6.1.4.1.12345.1.4";
                public const string Admin = "1.3.6.1.4.1.12345.1.5";
            }
        }
    }
}
