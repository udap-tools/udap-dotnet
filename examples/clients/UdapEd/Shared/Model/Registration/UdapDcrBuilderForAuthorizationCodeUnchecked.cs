#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Model.Registration;

namespace UdapEd.Shared.Model.Registration;

/// <summary>
/// This builder gives access to the underlying <see cref="UdapDynamicClientRegistrationDocument"/>.
/// It is intended for usage in constructing invalid documents.
/// </summary>
public class UdapDcrBuilderForAuthorizationCodeUnchecked : UdapDcrBuilderForAuthorizationCode
{
    public new UdapDynamicClientRegistrationDocument Document
    {
        get => base.Document;
        set => base.Document = value;
    }

    protected UdapDcrBuilderForAuthorizationCodeUnchecked(X509Certificate2 certificate, bool cancelRegistration) : base(cancelRegistration)
    {
        this.WithCertificate(certificate);
    }

    protected UdapDcrBuilderForAuthorizationCodeUnchecked(bool cancelRegistration) : base(cancelRegistration)
    {
    }

    public new static UdapDcrBuilderForAuthorizationCodeUnchecked Create(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForAuthorizationCodeUnchecked(cert, false);
    }

   
    public new static UdapDcrBuilderForAuthorizationCodeUnchecked Create()
    {
        return new UdapDcrBuilderForAuthorizationCodeUnchecked(false);
    }

    public new static UdapDcrBuilderForAuthorizationCodeUnchecked Cancel(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForAuthorizationCodeUnchecked(cert, true);
    }
    
    public new static UdapDcrBuilderForAuthorizationCodeUnchecked Cancel()
    {
        return new UdapDcrBuilderForAuthorizationCodeUnchecked(true);
    }

    public new UdapDcrBuilderForAuthorizationCode WithCertificate(X509Certificate2 certificate)
    {
        base.Certificate = certificate;

        return this;
    }
}