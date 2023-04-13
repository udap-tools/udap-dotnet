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

public interface IAnchorService
{
    Task<ICollection<Anchor>> Get(CancellationToken token = default);
    Task<Anchor> Get(int? id, CancellationToken token = default);
    Task<Anchor> Add(Anchor anchor, CancellationToken token = default);
    Task Update(Anchor anchor, CancellationToken token = default);
    Task<bool> Delete(long? id, CancellationToken token = default);
}

public class AnchorService: IAnchorService
{
    private IUdapDbAdminContext _dbContext;
    IUdapCertificateValidator<Anchor> _validator;

    public AnchorService(IUdapDbAdminContext dbContext, IUdapCertificateValidator<Anchor> validator)
    {
        _dbContext = dbContext;
        _validator = validator;
    }

    public async Task<Anchor> Add(Anchor anchor, CancellationToken token)
    {
        _validator.Validate(anchor);

        if (((DbContext)_dbContext).Database.IsRelational())
        {
            var anchors = await _dbContext.Anchors
                .Include(a => a.Community)
                .Where(a => a.Thumbprint == anchor.Thumbprint)
                .ToListAsync(cancellationToken: token);

            if (anchors.Any())
            {
                throw new DuplicateAnchorException($"Duplicate anchor.  Anchor exists in \"{anchors.First().Community.Name}\" community");
            }
        }

        _dbContext.Anchors.Add(anchor);
        await _dbContext.SaveChangesAsync(token);

        return anchor;
    }

    public async Task<bool> Delete(long? id, CancellationToken token)
    {
        var anchor = await _dbContext.Anchors
            .Include(a => a.AnchorCertifications)
            .SingleOrDefaultAsync(d => d.Id == id, token);

        if (anchor == null)
        {
            return false;
        }

        _dbContext.Anchors.Remove(anchor);
        
        await _dbContext.SaveChangesAsync(token);

        return true;
    }

    public async Task<Anchor> Get(int? id, CancellationToken token)
    {
        return await _dbContext.Anchors
            .Where(c => c.Id == id)
            .SingleAsync(cancellationToken: token);
    }

    public async Task<ICollection<Anchor>> Get(CancellationToken token = default)
    {
        return await _dbContext.Anchors.ToListAsync(cancellationToken: token);
    }

    public async Task Update(Anchor anchor, CancellationToken token)
    {
        // _validator.Validate(anchor);
        // var storedAnchor = await _dbContext.Anchors.SingleAsync(a => a.Id == anchor.Id, cancellationToken: token);
        // var entry = _dbContext.Anchors.Entry(storedAnchor);
        // entry.CurrentValues.SetValues(anchor);
        // await _dbContext.SaveChangesAsync(token);

        _validator.Validate(anchor);
        _dbContext.Anchors.Update(anchor);
        await _dbContext.SaveChangesAsync(token);
    }
}