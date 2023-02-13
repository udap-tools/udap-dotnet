#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src

COPY ["nuget.config", "."]
COPY ["Server/UdapEd.Server.csproj", "Server/"]
RUN dotnet restore "Server/UdapEd.Server.csproj"
COPY . .

WORKDIR "/src/Server"
RUN dotnet build "UdapEd.Server.csproj" -c Release -o /app/build


FROM build AS publish
RUN dotnet publish "UdapEd.Server.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENV ASPNETCORE_URLS=http://*:8080
ENTRYPOINT ["dotnet", "UdapEd.Server.dll"]