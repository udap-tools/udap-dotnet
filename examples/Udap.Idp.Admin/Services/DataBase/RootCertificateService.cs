using Microsoft.EntityFrameworkCore;
using Udap.Common;
using Udap.Server.DbContexts;
using Udap.Server.Entities;

namespace Udap.Idp.Admin.Services.DataBase;


public interface IRootCertificateService
{
    Task<ICollection<IntermediateCertificate>> Get(CancellationToken token = default);
    Task<IntermediateCertificate> Get(int? id, CancellationToken token = default);
    Task<IntermediateCertificate> Add(IntermediateCertificate intermediateCertificate, CancellationToken token = default);
    Task Update(IntermediateCertificate intermediateCertificate, CancellationToken token = default);
    Task<bool> Delete(long? id, CancellationToken token = default);
}


public class RootCertificateService : IRootCertificateService
{
    private IUdapDbAdminContext _dbContext;
    IUdapCertificateValidator<IntermediateCertificate> _validator;

    //TODO: validation for RootCert or RootCertificate should have special handling.
    // Like if an rootCertificate has a crl signed by a CA then you have to include it...  Well more testing anyway...
    public RootCertificateService(IUdapDbAdminContext dbContext, IUdapCertificateValidator<IntermediateCertificate> validator)
    {
        _dbContext = dbContext;
        _validator = validator;
    }

    public async Task<IntermediateCertificate> Add(IntermediateCertificate intermediateCertificate, CancellationToken token)
    {
        _validator.Validate(intermediateCertificate);

        if (((DbContext)_dbContext).Database.IsRelational())
        {
            var rootCertificates = await _dbContext.IntermediateCertificates
                .Where(a => a.Thumbprint == intermediateCertificate.Thumbprint)
                .ToListAsync(cancellationToken: token);

            if (rootCertificates.Any())
            {
                throw new DuplicateRootCertificateException($"Duplicate rootCertificate.");
            }
        }

        _dbContext.IntermediateCertificates.Add(intermediateCertificate);
        await _dbContext.SaveChangesAsync(token);

        return intermediateCertificate;
    }

    public async Task<bool> Delete(long? id, CancellationToken token)
    {
        var rootCertificate = await _dbContext.IntermediateCertificates
            .SingleOrDefaultAsync(d => d.Id == id, token);

        if (rootCertificate == null)
        {
            return false;
        }

        _dbContext.IntermediateCertificates.Remove(rootCertificate);

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