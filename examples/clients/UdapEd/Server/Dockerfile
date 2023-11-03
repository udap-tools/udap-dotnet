#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
ARG TAG_NAME
WORKDIR /app
EXPOSE 8080
EXPOSE 443
COPY ./Server/EMRDirectTestCA.crt /etc/ssl/certs
COPY ./Server/EMRDirectTestClientSubCA.crt /etc/ssl/certs
COPY ./Server/SureFhirLabs_CA.cer /etc/ssl/certs
COPY ./Server/ngnix-proxy-TestCA.cer /etc/ssl/certs
RUN update-ca-certificates


FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src

ENV GCPDeploy=true
#this technique of setting env to control version is not working yet.
ARG TAG_NAME
ENV TAG_NAME_ENV=$TAG_NAME

COPY ["nuget.config", "."]
COPY ["Server/UdapEd.Server.csproj", "Server/"]
COPY ["Client/UdapEd.Client.csproj", "Client/"]
COPY ["Shared/UdapEd.Shared.csproj", "Shared/"]

RUN dotnet restore "Client/UdapEd.Client.csproj"
RUN dotnet restore "Shared/UdapEd.Shared.csproj"
RUN dotnet restore "Server/UdapEd.Server.csproj"
COPY . .

RUN dotnet build "Server/UdapEd.Server.csproj" -c Release  -o /app/build 


FROM build AS publish
ARG TAG_NAME
RUN dotnet publish "Server/UdapEd.Server.csproj" --version-suffix 99 -c Release -o /app/publish /p:UseAppHost=false 

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENV ASPNETCORE_URLS=http://*:8080
ENTRYPOINT ["dotnet", "UdapEd.Server.dll"]
