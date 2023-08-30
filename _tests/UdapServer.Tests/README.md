

Notes:

Sqlite schema for PersistedGrantDbContext and ConfigurationDbContext from Duende IdentityServer.

Because these tests need a full db build with the above DB contexts and the UdapDbContext the following is the strategy.

 UdapDbContext is created with ```await udapContext.Database.EnsureCreatedAsync();``` and then 
PersistedGrantDbContext and ConfigurationDbContext are migrate like the following

```
await persistedGrantDbContext.Database.EnsureCreatedAsync()
await configurationDbContext.Database.EnsureCreatedAsync()
```

The dotnet-ef tooling and Sqlite do not support migrations.  We can brute force make this happen.
Copy the migrations created for SQL server in the ../../migrations/UdapDb.SqlServer to this project.  

Fix up all the varchar entries to TEXT. Bit to Enabled.  

Here is another example of a change.

Before:
```
Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
```

After:
```
Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                   
```

See the existing code in the test for example.

