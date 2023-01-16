using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Udap.Model.Registration;
public class UdapCertificationAndEndorsementDocument
{
    public string? Issuer { get; set; }
    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    /// <remarks>Use <see cref="System.IdentityModel.Tokens.Jwt.JsonExtensions.Serializer"/> to customize JSON serialization.</remarks>
    public virtual string SerializeToJson()
    {
        return JsonExtensions.SerializeToJson(this);
    }

    /// <summary>
    /// Encodes this instance as Base64UrlEncoded JSON.
    /// </summary>
    /// <returns>Base64UrlEncoded JSON.</returns>
    /// <remarks>Use <see cref="System.IdentityModel.Tokens.Jwt.JsonExtensions.Serializer"/> to customize JSON serialization.</remarks>
    public virtual string Base64UrlEncode()
    {
        return Base64UrlEncoder.Encode(SerializeToJson());
    }
}
