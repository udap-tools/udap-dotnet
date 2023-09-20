#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Validation;
using Microsoft.EntityFrameworkCore;
using Udap.Server.DbContexts;
using Udap.Server.Options;
using Udap.Server.Stores;
using Udap.Server.Validation;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddUdapDbContext(
        this IServiceCollection services,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null)
    {
        return services.AddUdapDbContext<UdapDbContext>(storeOptionAction);
    }

    public static IServiceCollection AddUdapDbContext<TContext>(
        this IServiceCollection services,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null)
        where TContext : DbContext, IUdapDbAdminContext, IUdapDbContext
    {
        var storeOptions = new UdapConfigurationStoreOptions();
        services.AddSingleton(storeOptions);
        storeOptionAction?.Invoke(storeOptions);

        if (storeOptions.ResolveDbContextOptions != null)
        {
            if (storeOptions.EnablePooling)
            {
                if (storeOptions.PoolSize.HasValue)
                {
                    services.AddDbContextPool<TContext>(storeOptions.ResolveDbContextOptions,
                        storeOptions.PoolSize.Value);
                }
                else
                {
                    services.AddDbContextPool<TContext>(storeOptions.ResolveDbContextOptions);
                }
            }
            else
            {
                services.AddDbContext<TContext>(storeOptions.ResolveDbContextOptions);
            }
        }
        else
        {
            if (storeOptions.EnablePooling)
            {
                if (storeOptions.PoolSize.HasValue)
                {
                    services.AddDbContextPool<TContext>(
                        dbCtxBuilder => { storeOptions.UdapDbContext?.Invoke(dbCtxBuilder); },
                        storeOptions.PoolSize.Value);
                }
                else
                {
                    services.AddDbContextPool<TContext>(
                        dbCtxBuilder => { storeOptions.UdapDbContext?.Invoke(dbCtxBuilder); });
                }
            }
            else
            {
                services.AddDbContext<TContext>(dbCtxBuilder =>
                {
                    storeOptions.UdapDbContext?.Invoke(dbCtxBuilder);
                });
            }
        }

        services.AddScoped<IUdapDbAdminContext>(sp => sp.GetRequiredService<TContext>());
        services.AddScoped<IUdapDbContext>(sp => sp.GetRequiredService<TContext>());

        return services;
    }

    public static IIdentityServerBuilder AddUdapConfigurationStore(
        this IIdentityServerBuilder builder,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null)
    {
        return builder.AddUdapConfigurationStore<UdapDbContext>(storeOptionAction);
    }

    public static IIdentityServerBuilder AddUdapConfigurationStore<TContext>(
        this IIdentityServerBuilder builder,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null)
        where TContext : DbContext, IUdapDbAdminContext, IUdapDbContext
    {
        builder.Services.AddUdapDbContext<TContext>(storeOptionAction);
        builder.AddUdapClientRegistrationStore<UdapClientRegistrationStore>();

        return builder;
    }

    public static IServiceCollection AddSmartV2Expander(this IServiceCollection services)
    {
        services.AddScoped<IScopeExpander, SmartV2Expander>();
        
        return services;
    }
}

