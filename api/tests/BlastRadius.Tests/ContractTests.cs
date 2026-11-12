using Testcontainers.PostgreSql;

namespace BlastRadius.Tests;

public class ContractTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Scenario_on_sqlite()
    {
        await using var factory = new ApiFactory();
        await ContractRunner.RunAsync(factory, output);
    }

    /// <summary>Same scenario through the EF migrations on PostgreSQL. Needs Docker; CI has it.</summary>
    [Fact]
    public async Task Scenario_on_postgres()
    {
        Assert.SkipUnless(DockerAvailable(), "Docker is not available");
        await using var pg = new PostgreSqlBuilder("postgres:17-alpine").Build();
        await pg.StartAsync(TestContext.Current.CancellationToken);
        await using var factory = new ApiFactory(pg.GetConnectionString());
        await ContractRunner.RunAsync(factory, output);
    }

    private static bool DockerAvailable()
    {
        try
        {
            return DotNet.Testcontainers.Configurations.TestcontainersSettings.OS.DockerEndpointAuthConfig != null;
        }
        catch
        {
            return false;
        }
    }
}
