rem  Run from this directory.  This always starts over.  Some day I will have to retain history.  Maybe... 

rmdir /S /Q "Udap/Server"
dotnet ef migrations add InitialSqlServerUdap  -c UdapDbContext -o Udap/Server/Migrations/SqlServer/UdapDb  --namespace=Udap.Server.Migrations.SqlServer.UdapDb -- --provider=SqlServer
dotnet ef migrations script -c UdapDbContext -o Udap/Server/Migrations/SqlServer/udapSqlServerDb.sql


dotnet ef migrations add InitialSqliteUdap  -c UdapDbContext -o Udap/Server/Migrations/Sqlite/UdapDb  --namespace=Udap.Server.Migrations.Sqlite.UdapDb -- --provider=Sqlite
dotnet ef migrations script -c UdapDbContext -o Udap/Server/Migrations/Sqlite/udapSqliteDb.sql