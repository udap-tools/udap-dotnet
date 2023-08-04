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

namespace Udap.Auth.Server.Admin.Services.DataBase
{
    public interface ICommunityService
    {
        Task<ICollection<Community>> Get(CancellationToken token = default);
        Task<Community> Get(int? id, CancellationToken token = default);
        Task<Community> Add(Community community, CancellationToken token = default);
        Task Update(Community community, CancellationToken token = default);
        Task<bool> Delete(int? id, CancellationToken token = default);
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

        public async Task<Community> Add(Community community, CancellationToken token)
        {
            // _validator.Validate(community);

            if (((DbContext)_dbContext).Database.IsRelational())
            {
                var communities = await _dbContext.Communities
                    .Where(c => c.Id == community.Id)
                    .ToListAsync(cancellationToken: token);

                if (communities.Any())
                {
                    throw new DuplicateCommunityException($"Duplicate anchor.  Anchor exists in \"{communities.First().Name}\" community");
                }
            }

            _dbContext.Communities.Add(community);
            await _dbContext.SaveChangesAsync(token);

            return community;
        }

        public async Task<bool> Delete(int? id, CancellationToken token)
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

        public async Task Update(Community community, CancellationToken token)
        {
            // _validator.Validate(community);
            _dbContext.Communities.Update(community);
            await _dbContext.SaveChangesAsync(token);
        }
    }
}
