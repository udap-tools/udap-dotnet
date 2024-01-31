REM  Run from this directory.  This always starts over.  Some day I will have to retain history.  Maybe... 

rmdir /S /Q "Udap/Server"
dotnet dotnet-ef migrations add InitialSqlServerUdap  -c UdapDbContext -o Udap/Server/Migrations/SqlServer/UdapDb  --namespace=Udap.Server.Migrations.SqlServer.UdapDb -- --provider=SqlServer
dotnet dotnet-ef migrations script -c UdapDbContext -o Udap/Server/Migrations/SqlServer/udapSqlServerDb.sql



