using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Config via env:
var allowedHosts = (Environment.GetEnvironmentVariable("ALLOW_HOSTS") ?? "")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    .Select(h => h.ToLowerInvariant())
    .ToHashSet();

var maxContentBytes = int.TryParse(Environment.GetEnvironmentVariable("MAX_CONTENT_BYTES"), out var m) ? m : 25_000_000; // 25MB
var timeoutSec = int.TryParse(Environment.GetEnvironmentVariable("TIMEOUT_SECONDS"), out var t) ? t : 30;

var handler = new SocketsHttpHandler
{
    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
    AllowAutoRedirect = false,               // avoid redirect loops
    ConnectTimeout = TimeSpan.FromSeconds(timeoutSec)
};
var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(timeoutSec) };

// ---- CORS config (via env CORS_ORIGINS="https://foo.com,https://bar.com"; "*" allowed) ----
var corsEnv = Environment.GetEnvironmentVariable("CORS_ORIGINS") ?? "*";
var corsOrigins = corsEnv
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

builder.Services.AddCors(options =>
{
    options.AddPolicy("proxy", policy =>
    {
        if (corsOrigins.Length == 1 && corsOrigins[0] == "*")
            policy.AllowAnyOrigin();
        else
            policy.WithOrigins(corsOrigins);

        policy.AllowAnyHeader()
              .AllowAnyMethod(); // GET, POST, OPTIONS, etc.
    });
});

var app = builder.Build();

// Enable CORS globally (handles preflight)
app.UseCors("proxy");

// Shared handler so POST and GET behave identically
async Task<IResult> HandleFetch(string rawUrl, HttpResponse res)
    {
    if (string.IsNullOrWhiteSpace(rawUrl))
        return Results.BadRequest("Body or query must contain a URL.");

    if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        return Results.BadRequest("Invalid URL.");

    if (uri.Scheme is not ("http" or "https"))
        return Results.BadRequest("Only http/https URLs are allowed.");

    // Optional allowlist
    if (allowedHosts.Count > 0 && !allowedHosts.Contains(uri.Host.ToLowerInvariant()))
        return Results.StatusCode((int)HttpStatusCode.Forbidden);

    // Resolve and block private/loopback/link-local/etc (basic SSRF guard)
    IPAddress[] addrs;
    try { addrs = await Dns.GetHostAddressesAsync(uri.DnsSafeHost); }
    catch { return Results.BadRequest("Unable to resolve host."); }

    foreach (var ip in addrs)
    {
        if (IsPrivateOrDisallowed(ip))
            return Results.StatusCode((int)HttpStatusCode.Forbidden);
    }

    // Build & send upstream request
    var upstream = new HttpRequestMessage(HttpMethod.Get, uri);
    upstream.Headers.UserAgent.ParseAdd("vpn-fetch-proxy/1.0");

    HttpResponseMessage upstreamResp;
    try
    {
        upstreamResp = await http.SendAsync(upstream, HttpCompletionOption.ResponseHeadersRead);
    }
    catch (TaskCanceledException)
    {
        return Results.StatusCode((int)HttpStatusCode.GatewayTimeout);
    }
    catch
    {
        return Results.StatusCode((int)HttpStatusCode.BadGateway);
    }

    // Copy status code
    res.StatusCode = (int)upstreamResp.StatusCode;

    HashSet<string> HopByHopHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection","Keep-Alive","Proxy-Authenticate","Proxy-Authorization",
        "TE","Trailers","Transfer-Encoding","Upgrade"
    };

    // Copy headers except hop-by-hop
    foreach (var header in upstreamResp.Headers)
        if (!HopByHopHeaders.Contains(header.Key))
            res.Headers[header.Key] = header.Value.ToArray();
    if (upstreamResp.Content.Headers.ContentType is MediaTypeHeaderValue ct)
        res.ContentType = ct.ToString();

    // Size-capped stream copy
    await using var src = await upstreamResp.Content.ReadAsStreamAsync();
    var buffered = new MemoryStream();
    var buffer = new byte[81920];
    int read; long total = 0;
    while ((read = await src.ReadAsync(buffer, 0, buffer.Length)) > 0)
    {
        total += read;
        if (total > maxContentBytes)
            return Results.StatusCode((int)HttpStatusCode.RequestEntityTooLarge);
        buffered.Write(buffer, 0, read);
    }
    buffered.Position = 0;
    await buffered.CopyToAsync(res.Body);

    return Results.Empty;
}

// ---- routes ----

// Existing POST /fetch (unchanged behavior; now calls shared handler)
app.MapPost("/fetch", async (HttpRequest req, HttpResponse res) =>
{
    string rawUrl;

    if (req.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true)
        {
        using var reader = new StreamReader(req.Body, Encoding.UTF8);
        var json = await reader.ReadToEndAsync();
        var doc = System.Text.Json.JsonDocument.Parse(json);
        rawUrl = doc.RootElement.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        }
    else
    {
        using var reader = new StreamReader(req.Body, Encoding.UTF8);
        rawUrl = (await reader.ReadToEndAsync()).Trim();
    }

    return await HandleFetch(rawUrl, res);
});

// NEW: GET /fetch?url=https://example.com   (also accepts ?u=...)
app.MapGet("/fetch", async (HttpRequest req, HttpResponse res) =>
{
    var rawUrl = req.Query.TryGetValue("url", out var v1) ? v1.ToString()
               : req.Query.TryGetValue("u", out var v2) ? v2.ToString()
               : null;

    if (string.IsNullOrWhiteSpace(rawUrl))
        return Results.BadRequest("Provide the target URL as ?url=... (or ?u=...).");

    return await HandleFetch(rawUrl!, res);
});

app.Run();

static bool IsPrivateOrDisallowed(IPAddress ip)
{
    if (IPAddress.IsLoopback(ip)) return true;

    if (ip.AddressFamily == AddressFamily.InterNetwork) // IPv4
    {
        var bytes = ip.GetAddressBytes();
        // 10.0.0.0/8
        if (bytes[0] == 10) return true;
        // 172.16.0.0/12
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        // 192.168.0.0/16
        if (bytes[0] == 192 && bytes[1] == 168) return true;
        // 127.0.0.0/8 (already caught by IsLoopback, but keep)
        if (bytes[0] == 127) return true;
        // link-local 169.254.0.0/16
        if (bytes[0] == 169 && bytes[1] == 254) return true;
    }
    else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
    {
        if (ip.IsIPv6LinkLocal) return true;
        if (ip.IsIPv6SiteLocal) return true;
        if (ip.IsIPv6Multicast) return true;
        if (ip.Equals(IPAddress.IPv6Loopback)) return true;
        // Unique local fc00::/7
        var bytes = ip.GetAddressBytes();
        if ((bytes[0] & 0xFE) == 0xFC) return true;
    }
    return false;
}

