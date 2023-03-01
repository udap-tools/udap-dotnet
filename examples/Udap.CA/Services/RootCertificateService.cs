#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Udap.CA.DbContexts;
using Udap.CA.Mappers;

namespace Udap.CA.Services;

public class RootCertificateService
{
    private IUdapCaContext _dbContext;
    private IMapper _autoMapper;
    private ILogger<CommunityService> _logger;

    public RootCertificateService(IUdapCaContext dbContext, IMapper autoMapper, ILogger<CommunityService> logger)
    {
        _dbContext = dbContext;
        _autoMapper = autoMapper;
        _logger = logger;
    }

    public async Task<ICollection<ViewModel.RootCertificate>> Get(CancellationToken token = default)
    {
        var rootCertificates = await _dbContext.RootCertificates
            .ToListAsync(cancellationToken: token);

        return _autoMapper.Map<ICollection<ViewModel.RootCertificate>>(rootCertificates);
    }

    public async Task<ViewModel.RootCertificate> Create(ViewModel.RootCertificate rootCertificate, CancellationToken token = default)
    {
        var entity = rootCertificate.ToEntity();
        await _dbContext.RootCertificates.AddAsync(entity, token);
        await _dbContext.SaveChangesAsync(token);

        return entity.ToViewModel();
    }

    public async Task Update(ViewModel.RootCertificate rootCertificate, CancellationToken token = default)
    {
        var entity = await _dbContext.RootCertificates
            .Where(c => c.Id == rootCertificate.Id)
            .SingleOrDefaultAsync(cancellationToken: token);

        if (entity == null)
        {
            _logger.LogDebug($"No Community Id {rootCertificate.Id} found in database. Update failed.");

            return;
        }

        entity.Enabled = rootCertificate.Enabled;
        
        await _dbContext.SaveChangesAsync(token);
    }

    public async Task<bool> Delete(int id, CancellationToken token = default)
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
}