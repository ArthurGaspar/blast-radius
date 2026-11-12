using BlastRadius.Api.Data;
using BlastRadius.Api.Notifications;

namespace BlastRadius.Tests;

public class NotifierTests
{
    private static readonly Site Lab = new() { Name = "Lab", Kind = "office" };
    private static readonly Asset Ssh = new() { Label = "Bastion sshd", SiteId = Lab.Id, ProductKey = "openssh", Version = "9.6p1" };

    private static Vulnerability Vuln(string severity, bool kev = false, double? epss = null) =>
        new() { Id = "CVE-2008-3844", Title = "OpenSSH packages signed in August 2008", Severity = severity, Kev = kev, Epss = epss };

    private static ExposureEvent Event(Vulnerability v, string basis = "range") => new("new_exposure", Guid.Empty, Ssh, Lab, v, basis);

    [Theory]
    [InlineData("range", true)]
    [InlineData("no-version", true)]
    [InlineData("no-bounds", false)]     // NVD names OpenSSH without versions: says nothing about 9.6p1
    [InlineData("incomparable", false)]  // e.g. a date-shaped bound against a release number
    public void Alerts_only_on_concrete_evidence(string basis, bool alerts)
    {
        var sub = new Subscription { Name = "Critical anywhere", MinSeverity = "critical" };
        Assert.Equal(alerts, Notifier.Passes(sub, Event(Vuln("critical"), basis)));
    }

    [Fact]
    public void Applies_every_filter()
    {
        var v = Vuln("high", kev: false, epss: 0.02);
        Assert.False(Notifier.Passes(new Subscription { Name = "x", MinSeverity = "critical" }, Event(v)));
        Assert.False(Notifier.Passes(new Subscription { Name = "x", MinSeverity = "low", KevOnly = true }, Event(v)));
        Assert.False(Notifier.Passes(new Subscription { Name = "x", MinSeverity = "low", MinEpss = 0.1 }, Event(v)));
        Assert.False(Notifier.Passes(new Subscription { Name = "x", MinSeverity = "low", Keyword = "deserialization" }, Event(v)));
        Assert.False(Notifier.Passes(new Subscription { Name = "x", MinSeverity = "low", Scope = "site", ScopeSiteId = Guid.NewGuid() }, Event(v)));
        Assert.False(Notifier.Passes(new Subscription { Name = "x", MinSeverity = "low", Scope = "product", ScopeProductKey = "nginx" }, Event(v)));
        Assert.False(Notifier.Passes(new Subscription { Name = "x", MinSeverity = "low", Active = false }, Event(v)));
        Assert.True(Notifier.Passes(new Subscription { Name = "x", MinSeverity = "low", Keyword = "openssh", Scope = "product", ScopeProductKey = "openssh" }, Event(v)));
    }
}
