# Build from the repository root (the API ships shared/catalog.json):
#   docker build -f api/Dockerfile .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY shared/catalog.json shared/catalog.json
COPY api/global.json api/
COPY api/src/BlastRadius.Api/BlastRadius.Api.csproj api/src/BlastRadius.Api/
RUN dotnet restore api/src/BlastRadius.Api/BlastRadius.Api.csproj
COPY api/src api/src
RUN dotnet publish api/src/BlastRadius.Api/BlastRadius.Api.csproj -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /out .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
USER app
ENTRYPOINT ["dotnet", "BlastRadius.Api.dll"]
