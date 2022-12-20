using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Udap.CA.DbContexts;
using Udap.CA.Mappers;


namespace Udap.CA.Services;

public class CommunityService
{
    private IUdapCaContext _dbContext;
    private IMapper _autoMapper;
    private ILogger<CommunityService> _logger;

    public CommunityService(IUdapCaContext dbContext, IMapper autoMapper, ILogger<CommunityService> logger)
    {
        _dbContext = dbContext;
        _autoMapper = autoMapper;
        _logger = logger;
    }

    public async Task<ICollection<ViewModel.Community>> Get(CancellationToken token = default)
    {
        var communties = await _dbContext.Communities
            .Include(c => c.RootCertificates)
            .ToListAsync(cancellationToken: token);

        return _autoMapper.Map<ICollection<ViewModel.Community>>(communties);
    }

    public async Task<ViewModel.Community> Create(ViewModel.Community community, CancellationToken token = default)
    {
        var entity = community.ToEntity();
        _dbContext.Communities.Add(entity);
        await _dbContext.SaveChangesAsync(token);
        
        return entity.ToViewModel();
    }

    public async Task Update(ViewModel.Community community, CancellationToken token = default)
    {
        var entity = await _dbContext.Communities
            .Where(c => c.Id == community.Id)
            .SingleOrDefaultAsync(cancellationToken: token);

        if (entity == null)
        {
            _logger.LogDebug($"No Community Id {community.Id} found in database. Update failed.");

            return;
        }

        entity.Enabled = community.Enabled;
        entity.Name = community.Name;
        
        await _dbContext.SaveChangesAsync(token);
    }

    public async Task<bool> Delete(int id, CancellationToken token = default)
    {
        var community = await _dbContext.Communities
            .SingleOrDefaultAsync(d => d.Id == id, token);

        if (community == null)
        {
            return false;
        }

        _dbContext.Communities.Remove(community);

        await _dbContext.SaveChangesAsync(token);

        return true;
    }
}