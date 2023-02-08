#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace UdapClient.Shared.Model;
public enum Oauth2FlowEnum { authorization_code, client_credentials }

public enum CertLoadedEnum { Negative, Positive, InvalidPassword }