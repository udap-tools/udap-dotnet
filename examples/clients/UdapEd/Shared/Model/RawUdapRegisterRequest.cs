using Udap.Model.Registration;

namespace UdapEd.Shared.Model;

/// <summary>
/// Semantic naming to indicate that <see cref="UdapRegisterRequest.SoftwareStatement"/>
/// is not in raw format before being signed.
/// </summary>
public class RawUdapRegisterRequest : UdapRegisterRequest
{
}
