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
public class UdapDcrBuilderForClientCredentialsUnchecked : UdapDcrBuilderForClientCredentials
{
    public new UdapDynamicClientRegistrationDocument Document
    {
        get => base.Document;
        set => base.Document = value;
    }

    protected UdapDcrBuilderForClientCredentialsUnchecked(X509Certificate2 certificate, bool cancelRegistration) : base(cancelRegistration)
    {
        this.WithCertificate(certificate);
    }

    protected UdapDcrBuilderForClientCredentialsUnchecked(bool cancelRegistration) :base(cancelRegistration)
    {
    }

    public new static UdapDcrBuilderForClientCredentialsUnchecked Create(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForClientCredentialsUnchecked(cert, false);
    }
   
    public new static UdapDcrBuilderForClientCredentialsUnchecked Create()
    {
        return new UdapDcrBuilderForClientCredentialsUnchecked(false);
    }

    public new static UdapDcrBuilderForClientCredentialsUnchecked Cancel(X509Certificate2 cert)
    {
        return new UdapDcrBuilderForClientCredentialsUnchecked(cert, true);
    }
    
    public new static UdapDcrBuilderForClientCredentialsUnchecked Cancel()
    {
        return new UdapDcrBuilderForClientCredentialsUnchecked(true);
    }

    public new UdapDcrBuilderForClientCredentialsUnchecked WithCertificate(X509Certificate2 certificate)
    {
        base.Certificate = certificate;

        return this;
    }
}