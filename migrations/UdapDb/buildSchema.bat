rem  Run from this directory.  This always starts over.  Some day I will have to retain history.  Maybe... 

rmdir /S /Q "Udap/Server"
dotnet ef migrations add InitialUdap  -c UdapDbContext -o Udap/Server/Migrations/UdapDb   --namespace=Udap.Server.Migrations.UdapDb
dotnet ef migrations script -c UdapDbContext -o Udap/Server/Migrations/UdapDb.sql


