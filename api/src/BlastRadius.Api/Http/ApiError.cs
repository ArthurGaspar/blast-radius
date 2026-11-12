using System.Security.Claims;

namespace BlastRadius.Api.Http;

/// <summary>A rule violation with a stable code shared with the web client.</summary>
public sealed class ApiError(int status, string code, string message) : Exception(message)
{
    public int Status { get; } = status;
    public string Code { get; } = code;

    public static ApiError NotFound(string what) => new(404, "not-found", $"{what} not found");
    public static ApiError Invalid(string message) => new(400, "validation", message);
    public static ApiError Conflict(string code, string message) => new(409, code, message);
}

public static class ApiErrorExtensions
{
    public static Guid UserId(this ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue("sub")
                   ?? throw new ApiError(401, "auth.required", "Sign in first"));

    /// <summary>Turns <see cref="ApiError"/> into RFC 7807 problem details with a "code" extension.</summary>
    public static IApplicationBuilder UseApiErrors(this IApplicationBuilder app) => app.Use(async (ctx, next) =>
    {
        try
        {
            await next();
        }
        catch (ApiError e) when (!ctx.Response.HasStarted)
        {
            ctx.Response.StatusCode = e.Status;
            await Results.Problem(statusCode: e.Status, detail: e.Message, extensions: new Dictionary<string, object?> { ["code"] = e.Code })
                .ExecuteAsync(ctx);
        }
        catch (BadHttpRequestException e) when (!ctx.Response.HasStarted)
        {
            await Results.Problem(statusCode: 400, detail: "Request body is missing or malformed",
                extensions: new Dictionary<string, object?> { ["code"] = "validation" }).ExecuteAsync(ctx);
            _ = e;
        }
    });
}
