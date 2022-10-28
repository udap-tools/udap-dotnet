using Microsoft.EntityFrameworkCore;
using Udap.Server.DbContexts;
using Udap.Server.Entitiies;

namespace Udap.Idp.Admin.Services.DataBase
{
    public interface ICommunityService
    {
        Task<ICollection<Community>> Get(CancellationToken token = default);
        Task<Community> Get(int? id, CancellationToken token = default);
        Task<Community> Add(Community community, CancellationToken token = default);
        Task<Community> Update(Community community, CancellationToken token = default);
        Task<bool> Delete(long? id, CancellationToken token = default);
    }
    public class CommunityService : ICommunityService
    {
        private IUdapDbAdminContext _dbContext;
        IUdapAdminCommunityValidator _validator;

        public CommunityService(IUdapDbAdminContext dbContext, IUdapAdminCommunityValidator validator)
        {
            _dbContext = dbContext;
            _validator = validator;
        }

        public Task<Community> Add(Community community, CancellationToken token)
        {
            throw new NotImplementedException();
        }

        public Task<bool> Delete(long? id, CancellationToken token)
        {
            throw new NotImplementedException();
        }

        public async Task<Community> Get(int? id, CancellationToken token)
        {
            return await _dbContext.Communities
                .Where(c => c.Id == id)
                .SingleAsync(cancellationToken: token);
        }

        public async Task<ICollection<Community>> Get(CancellationToken token = default)
        {
            return await _dbContext.Communities
                .Include(c => c.Anchors)
                .ToListAsync(cancellationToken: token);
        }

        public Task<Community> Update(Community community, CancellationToken token)
        {
            throw new NotImplementedException();
        }
    }
}
