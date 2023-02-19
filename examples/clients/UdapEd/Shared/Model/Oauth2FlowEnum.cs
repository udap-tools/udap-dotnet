#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapEd.Shared.Model;
public enum Oauth2FlowEnum { client_credentials, authorization_code }

public enum CertLoadedEnum { Negative, Positive, InvalidPassword }