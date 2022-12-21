#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["NuGet.Config", "."]
COPY ["examples/Udap.Idp/Udap.Idp.csproj", "examples/Udap.Idp/"]
COPY ["Udap.Server/Udap.Server.csproj", "Udap.Server/"]
COPY ["Udap.Client/Udap.Client.csproj", "Udap.Client/"]
COPY ["Udap.Common/Udap.Common.csproj", "Udap.Common/"]
RUN dotnet restore "examples/Udap.Idp/Udap.Idp.csproj"
COPY . .
WORKDIR "/src/examples/Udap.Idp"
RUN dotnet build "Udap.Idp.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Udap.Idp.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Udap.Idp.dll"]