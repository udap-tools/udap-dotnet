using Microsoft.EntityFrameworkCore;
using Udap.Common;
using Udap.Server.DbContexts;
using Udap.Server.Entities;

namespace Udap.Idp.Admin.Services.DataBase;


public interface IRootCertificateService
{
    Task<ICollection<RootCertificate>> Get(CancellationToken token = default);
    Task<RootCertificate> Get(int? id, CancellationToken token = default);
    Task<RootCertificate> Add(RootCertificate rootCertificate, CancellationToken token = default);
    Task<RootCertificate> Update(RootCertificate rootCertificate, CancellationToken token = default);
    Task<bool> Delete(long? id, CancellationToken token = default);
}


public class RootCertificateService : IRootCertificateService
{
    private IUdapDbAdminContext _dbContext;
    IUdapCertificateValidator<RootCertificate> _validator;

    //TODO: validation for RootCert or RootCertificate should have special handling.
    // Like if an rootCertificate has a crl signed by a CA then you have to include it...  Well more testing anyway...
    public RootCertificateService(IUdapDbAdminContext dbContext, IUdapCertificateValidator<RootCertificate> validator)
    {
        _dbContext = dbContext;
        _validator = validator;
    }

    public async Task<RootCertificate> Add(RootCertificate rootCertificate, CancellationToken token)
    {
        _validator.Validate(rootCertificate);

        if (((DbContext)_dbContext).Database.IsRelational())
        {
            var rootCertificates = await _dbContext.RootCertificates
                .Where(a => a.Thumbprint == rootCertificate.Thumbprint)
                .ToListAsync(cancellationToken: token);

            if (rootCertificates.Any())
            {
                throw new DuplicateRootCertificateException($"Duplicate rootCertificate.");
            }
        }

        _dbContext.RootCertificates.Add(rootCertificate);
        await _dbContext.SaveChangesAsync(token);

        return rootCertificate;
    }

    public async Task<bool> Delete(long? id, CancellationToken token)
    {
        var rootCertificate = await _dbContext.RootCertificates
            .SingleOrDefaultAsync(d => d.Id == id, token);

        if (rootCertificate == null)
        {
            return false;
        }

        _dbContext.RootCertificates.Remove(rootCertificate);

        await _dbContext.SaveChangesAsync(token);

        return true;
    }

    public async Task<RootCertificate> Get(int? id, CancellationToken token)
    {
        return await _dbContext.RootCertificates
            .Where(c => c.Id == id)
            .SingleAsync(cancellationToken: token);
    }

    public async Task<ICollection<RootCertificate>> Get(CancellationToken token = default)
    {
        return await _dbContext.RootCertificates.ToListAsync(cancellationToken: token);
    }

    public Task<RootCertificate> Update(RootCertificate rootCertificate, CancellationToken token)
    {
        throw new NotImplementedException();
    }
}