﻿#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using IdentityModel.Client;
using Udap.Model.UdapAuthenticationExtensions;

namespace Udap.Model.Access;


public class UdapClientCredentialsTokenRequest : ClientCredentialsTokenRequest
{
    [JsonPropertyName(UdapConstants.RegistrationRequestBody.Udap)]
    public string Udap { get; set; } = UdapConstants.UdapVersionsSupportedValue;
}

public class UdapAuthorizationCodeTokenRequest : AuthorizationCodeTokenRequest
{
    [JsonPropertyName(UdapConstants.RegistrationRequestBody.Udap)]
    public string Udap { get; set; } = UdapConstants.UdapVersionsSupportedValue;
}