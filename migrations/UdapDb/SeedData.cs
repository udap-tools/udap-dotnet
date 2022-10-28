using Microsoft.EntityFrameworkCore;
using Udap.Server.DbContexts;

namespace UdapDb
{
    public class SeedData
    {
        /// <summary>
        /// No data yet but maybe in future there will be a need to populated some template data.
        /// </summary>
        /// <param name="serviceProvider"></param>
        public static void EnsureSeedData(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.GetService<IServiceScopeFactory>()?.CreateScope();
            using var context = scope?.ServiceProvider.GetService<UdapDbContext>();
            context?.Database.Migrate();
        }
    }
}
