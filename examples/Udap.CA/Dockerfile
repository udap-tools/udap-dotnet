#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

ENV GCPDeploy=true
COPY ["nuget.config", "."]
COPY ["Udap.CA.csproj", "."]
RUN dotnet restore "Udap.CA.csproj"
COPY . .

RUN dotnet build "Udap.CA.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Udap.CA.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENV ASPNETCORE_URLS=http://*:8080
ENTRYPOINT ["dotnet", "Udap.CA.dll"]