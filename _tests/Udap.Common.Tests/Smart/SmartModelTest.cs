using FluentAssertions;
using System.Text.Json;
using Udap.Smart.Model;

namespace Udap.Common.Tests.Smart; 
public class SmartModelTest
{
    private string modelConfigSource = @"
   {
  ""issuer"": ""https://host.docker.internal:5002"",
  ""jwks_uri"": ""https://host.docker.internal:5002/.well-known/openid-configuration/jwks"",
  ""authorization_endpoint"": ""https://host.docker.internal:5002/connect/authorize"",
  ""token_endpoint"": ""https://host.docker.internal:5002/connect/token"",
  ""token_endpoint_auth_methods_supported"": [
    ""udap_pki_jwt"",
    ""client_secret_basic"",
    ""private_key_jwt""
  ],
  ""grant_types_supported"": [
    ""authorization_code"",
    ""client_credentials"",
    ""refresh_token""
  ],
  ""registration_endpoint"": ""https://host.docker.internal:5002/connect/register"",
  ""scopes_supported"": [ ""openid"", ""profile"", ""launch"", ""launch/patient"", ""patient/*.rs"", ""user/*.rs"", ""offline_access"" ],
  ""response_types_supported"": [ ""code"" ],
  ""management_endpoint"": ""https://localhost:7074/user/manage"",
  ""introspection_endpoint"": ""https://host.docker.internal:5002/connect/introspect"",
  ""revocation_endpoint"": ""https://host.docker.internal:5002/connect/revoke"",
  ""code_challenge_methods_supported"": [ ""S256"" ],
  ""capabilities"": [
    ""launch-ehr"",
    ""permission-patient"",
    ""permission-v2"",
    ""client-public"",
    ""client-confidential-symmetric"",
    ""context-ehr-patient"",
    ""sso-openid-connect""
  ]
}";

    [Fact]
    public void DeserializeSmartMetadata()
    {
        var smartMetadata = JsonSerializer.Deserialize<SmartMetadata>(modelConfigSource);
        smartMetadata!.issuer.Should().Be("https://host.docker.internal:5002");
    }
}
