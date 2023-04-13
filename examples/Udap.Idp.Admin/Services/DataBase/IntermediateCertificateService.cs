#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Udap.Common;
using Udap.Server.DbContexts;
using Udap.Server.Entities;

namespace Udap.Idp.Admin.Services.DataBase;


public interface IIntermediateCertificateService
{
    Task<ICollection<IntermediateCertificate>> Get(CancellationToken token = default);
    Task<IntermediateCertificate> Get(int? id, CancellationToken token = default);
    Task<IntermediateCertificate> Add(IntermediateCertificate intermediateCertificate, CancellationToken token = default);
    Task Update(IntermediateCertificate intermediateCertificate, CancellationToken token = default);
    Task<bool> Delete(long? id, CancellationToken token = default);
}


public class IntermediateCertificateService : IIntermediateCertificateService
{
    private readonly IUdapDbAdminContext _dbContext;
    readonly IUdapCertificateValidator<IntermediateCertificate> _validator;

    //TODO: validation for IntermediateCert or IntermediateCertificate should have special handling.
    // Like if an intermediateCertificate has a crl signed by a CA then you have to include it...  Well more testing anyway...
    public IntermediateCertificateService(IUdapDbAdminContext dbContext, IUdapCertificateValidator<IntermediateCertificate> validator)
    {
        _dbContext = dbContext;
        _validator = validator;
    }

    public async Task<IntermediateCertificate> Add(IntermediateCertificate intermediateCertificate, CancellationToken token)
    {
        _validator.Validate(intermediateCertificate);

        if (((DbContext)_dbContext).Database.IsRelational())
        {
            var intermediateCertificates = await _dbContext.IntermediateCertificates
                .Where(a => a.Thumbprint == intermediateCertificate.Thumbprint)
                .ToListAsync(cancellationToken: token);

            if (intermediateCertificates.Any())
            {
                throw new DuplicateIntermediateCertificateException($"Duplicate intermediateCertificate.");
            }
        }

        _dbContext.IntermediateCertificates.Add(intermediateCertificate);
        await _dbContext.SaveChangesAsync(token);

        return intermediateCertificate;
    }

    public async Task<bool> Delete(long? id, CancellationToken token)
    {
        var intermediateCertificate = await _dbContext.IntermediateCertificates
            .SingleOrDefaultAsync(d => d.Id == id, token);

        if (intermediateCertificate == null)
        {
            return false;
        }

        _dbContext.IntermediateCertificates.Remove(intermediateCertificate);

        await _dbContext.SaveChangesAsync(token);

        return true;
    }

    public async Task<IntermediateCertificate> Get(int? id, CancellationToken token)
    {
        return await _dbContext.IntermediateCertificates
            .Where(c => c.Id == id)
            .SingleAsync(cancellationToken: token);
    }

    public async Task<ICollection<IntermediateCertificate>> Get(CancellationToken token = default)
    {
        return await _dbContext.IntermediateCertificates.ToListAsync(cancellationToken: token);
    }

    public async Task Update(IntermediateCertificate intermediateCertificate, CancellationToken token)
    {
        _validator.Validate(intermediateCertificate);
        _dbContext.IntermediateCertificates.Update(intermediateCertificate);
        await _dbContext.SaveChangesAsync(token);
    }
}