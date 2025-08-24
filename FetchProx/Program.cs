using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Config via env:
var allowedHosts = (Environment.GetEnvironmentVariable("ALLOW_HOSTS") ?? "")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    .Select(h => h.ToLowerInvariant())
    .ToHashSet();

var maxContentBytes = int.TryParse(Environment.GetEnvironmentVariable("MAX_CONTENT_BYTES"), out var m) ? m : 25_000_000; // 25MB
var timeoutSec = int.TryParse(Environment.GetEnvironmentVariable("TIMEOUT_SECONDS"), out var t) ? t : 30;
var rateLimitRequests = int.TryParse(Environment.GetEnvironmentVariable("RATE_LIMIT_REQUESTS"), out var r) ? r : 100;
var rateLimitWindowMin = int.TryParse(Environment.GetEnvironmentVariable("RATE_LIMIT_WINDOW_MINUTES"), out var w) ? w : 1;

var handler = new SocketsHttpHandler
{
    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
    AllowAutoRedirect = false,               // avoid redirect loops
    ConnectTimeout = TimeSpan.FromSeconds(timeoutSec),
    ConnectCallback = async (context, cancellationToken) =>
    {
        // Resolve DNS and validate IPs at connection time to prevent DNS rebinding/TOCTOU
        IPAddress[] addrs;
        try 
        { 
            addrs = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken); 
        }
        catch 
        { 
            throw new HttpRequestException($"Unable to resolve host: {context.DnsEndPoint.Host}"); 
        }

        foreach (var ip in addrs)
        {
            if (IsPrivateOrDisallowed(ip))
                throw new HttpRequestException($"Connection to private/disallowed address blocked: {ip}");
        }

        // Connect using the first resolved address
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(addrs[0], context.DnsEndPoint.Port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket?.Dispose();
            throw;
        }
    }
};
var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(timeoutSec) };

// ---- CORS config (via env CORS_ORIGINS="https://foo.com,https://bar.com"; now requires explicit configuration) ----
var corsEnv = Environment.GetEnvironmentVariable("CORS_ORIGINS") ?? "";
var corsOrigins = corsEnv
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

// ---- Rate limiting config ----
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("default", config =>
    {
        config.PermitLimit = rateLimitRequests;
        config.Window = TimeSpan.FromMinutes(rateLimitWindowMin);
        config.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        config.QueueLimit = 0; // No queuing, immediate rejection
    });
    options.RejectionStatusCode = 429; // Too Many Requests
});

// Only configure CORS if origins are explicitly specified
if (corsOrigins.Length > 0)
{
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
}

var app = builder.Build();

// Enable rate limiting
app.UseRateLimiter();

// Enable CORS only if configured
if (corsOrigins.Length > 0)
{
    app.UseCors("proxy");
}

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

    // Copy headers except hop-by-hop, with validation
    foreach (var header in upstreamResp.Headers)
    {
        if (!HopByHopHeaders.Contains(header.Key) && 
            !header.Key.StartsWith(":") && // HTTP/2 pseudo headers
            header.Key.All(c => c > 31 && c < 127)) // ASCII printable only
        {
            res.Headers[header.Key] = header.Value.ToArray();
        }
    }
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
        try
        {
            var doc = System.Text.Json.JsonDocument.Parse(json);
            rawUrl = doc.RootElement.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        }
        catch (System.Text.Json.JsonException)
        {
            return Results.BadRequest("Invalid JSON format.");
        }
        }
    else
    {
        using var reader = new StreamReader(req.Body, Encoding.UTF8);
        rawUrl = (await reader.ReadToEndAsync()).Trim();
    }

    return await HandleFetch(rawUrl, res);
}).RequireRateLimiting("default");

// NEW: GET /fetch?url=https://example.com   (also accepts ?u=...)
app.MapGet("/fetch", async (HttpRequest req, HttpResponse res) =>
{
    var rawUrl = req.Query.TryGetValue("url", out var v1) ? v1.ToString()
               : req.Query.TryGetValue("u", out var v2) ? v2.ToString()
               : null;

    if (string.IsNullOrWhiteSpace(rawUrl))
        return Results.BadRequest("Provide the target URL as ?url=... (or ?u=...).");

    return await HandleFetch(rawUrl!, res);
}).RequireRateLimiting("default");

app.Run();

static bool IsPrivateOrDisallowed(IPAddress ip)
{
    if (IPAddress.IsLoopback(ip)) return true;

    if (ip.AddressFamily == AddressFamily.InterNetwork) // IPv4
    {
        var bytes = ip.GetAddressBytes();
        // 0.0.0.0/8 - this network
        if (bytes[0] == 0) return true;
        // 10.0.0.0/8
        if (bytes[0] == 10) return true;
        // 100.64.0.0/10 - carrier NAT
        if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return true;
        // 127.0.0.0/8 (already caught by IsLoopback, but keep)
        if (bytes[0] == 127) return true;
        // link-local 169.254.0.0/16
        if (bytes[0] == 169 && bytes[1] == 254) return true;
        // 172.16.0.0/12
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        // 192.168.0.0/16
        if (bytes[0] == 192 && bytes[1] == 168) return true;
        // 224.0.0.0/4 - multicast and reserved (224-255)
        if (bytes[0] >= 224) return true;
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

