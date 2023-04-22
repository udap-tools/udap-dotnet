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
    Task<ICollection<Intermediate>> Get(CancellationToken token = default);
    Task<Intermediate> Get(int? id, CancellationToken token = default);
    Task<Intermediate> Add(Intermediate intermediates, CancellationToken token = default);
    Task Update(Intermediate intermediates, CancellationToken token = default);
    Task<bool> Delete(long? id, CancellationToken token = default);
}


public class IntermediateCertificateService : IIntermediateCertificateService
{
    private readonly IUdapDbAdminContext _dbContext;
    readonly IUdapCertificateValidator<Intermediate> _validator;

    //TODO: validation for IntermediateCert or Intermediates should have special handling.
    // Like if an intermediates has a crl signed by a CA then you have to include it...  Well more testing anyway...
    public IntermediateCertificateService(IUdapDbAdminContext dbContext, IUdapCertificateValidator<Intermediate> validator)
    {
        _dbContext = dbContext;
        _validator = validator;
    }

    public async Task<Intermediate> Add(Intermediate intermediates, CancellationToken token)
    {
        _validator.Validate(intermediates);

        if (((DbContext)_dbContext).Database.IsRelational())
        {
            var intermediateCertificates = await _dbContext.IntermediateCertificates
                .Where(a => a.Thumbprint == intermediates.Thumbprint)
                .ToListAsync(cancellationToken: token);

            if (intermediateCertificates.Any())
            {
                throw new DuplicateIntermediateCertificateException($"Duplicate intermediates.");
            }
        }

        _dbContext.IntermediateCertificates.Add(intermediates);
        await _dbContext.SaveChangesAsync(token);

        return intermediates;
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

    public async Task<Intermediate> Get(int? id, CancellationToken token)
    {
        return await _dbContext.IntermediateCertificates
            .Where(c => c.Id == id)
            .SingleAsync(cancellationToken: token);
    }

    public async Task<ICollection<Intermediate>> Get(CancellationToken token = default)
    {
        return await _dbContext.IntermediateCertificates.ToListAsync(cancellationToken: token);
    }

    public async Task Update(Intermediate intermediates, CancellationToken token)
    {
        _validator.Validate(intermediates);
        _dbContext.IntermediateCertificates.Update(intermediates);
        await _dbContext.SaveChangesAsync(token);
    }
}