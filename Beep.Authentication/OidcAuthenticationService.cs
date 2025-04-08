using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Claims;


namespace Beep.Authentication
{
    /// <summary>
    /// Authenticates against Duende IdentityServer (or any standard OIDC provider)
    /// using Resource Owner Password flow, but with manual HTTP calls (no IdentityModel).
    /// </summary>
    public class OidcAuthenticationService : IAuthenticationService
    {
        private readonly HttpClient _client;
        private readonly string _authority;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _scope;

        private string? _currentAccessToken;

        public OidcAuthenticationService(
            string authority,
            string clientId,
            string clientSecret,
            string scope)
        {
            _authority = authority.TrimEnd('/');
            _clientId = clientId;
            _clientSecret = clientSecret;
            _scope = scope;

            _client = new HttpClient();
        }

        /// <summary>
        /// Resource Owner Password Credential Flow
        /// Note: Not recommended for public clients in production.
        /// </summary>
        public async Task<string?> AuthenticateAsync(string username, string password)
        {
            // 1) Fetch discovery doc
            var discovery = await GetDiscoveryDocumentAsync();
            if (discovery == null || string.IsNullOrEmpty(discovery.TokenEndpoint))
            {
                Console.WriteLine("Discovery failed or no token endpoint found.");
                return null;
            }

            // 2) Construct ROPC request
            var fields = new Dictionary<string, string>
            {
                { "grant_type", "password" },
                { "username", username },
                { "password", password },
                { "client_id", _clientId },
                { "scope", _scope }
            };
            // client_secret if it's a confidential client
            if (!string.IsNullOrEmpty(_clientSecret))
            {
                fields["client_secret"] = _clientSecret;
            }

            using var content = new FormUrlEncodedContent(fields);

            // 3) Send request to token endpoint
            var response = await _client.PostAsync(discovery.TokenEndpoint, content);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Token request error: {response.StatusCode} => {body}");
                return null;
            }

            // 4) Parse JSON for "access_token"
            var json = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("access_token", out var accessProp))
            {
                Console.WriteLine("No 'access_token' in JSON.");
                return null;
            }

            _currentAccessToken = accessProp.GetString();
            return _currentAccessToken;
        }

        /// <summary>
        /// Simple parse of the JWT. For real signature validation, fetch the JWKS keys 
        /// and use Microsoft.IdentityModel.Tokens to validate.
        /// </summary>
        public async Task<UserInfo?> ValidateTokenAsync(string token)
        {
            if (string.IsNullOrEmpty(token)) return null;

            try
            {
                var handler = new JwtSecurityTokenHandler();
                if (!handler.CanReadToken(token))
                {
                    Console.WriteLine("Invalid JWT format.");
                    return null;
                }

                var jwt = handler.ReadJwtToken(token);

                // Basic parse of claims. Real usage => signature verify, expiration check, etc.
                var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                var name = jwt.Claims.FirstOrDefault(c => c.Type == "name"
                                                      || c.Type == ClaimTypes.Name
                                                      || c.Type == "preferred_username")?.Value;

                var roles = jwt.Claims
                    .Where(c => c.Type == "role" || c.Type == ClaimTypes.Role)
                    .Select(c => c.Value).ToList();

                var additional = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var c in jwt.Claims)
                {
                    if (c.Type is "sub" or "name" or "preferred_username" or "role")
                        continue;
                    additional[c.Type] = c.Value;
                }

                return new UserInfo
                {
                    UserId = sub,
                    Username = name,
                    Roles = roles,
                    AdditionalClaims = additional
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ValidateToken error: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Revokes the token if the IdentityServer supports token revocation, else just clears local store.
        /// </summary>
        public async Task LogoutAsync()
        {
            if (string.IsNullOrEmpty(_currentAccessToken))
                return;

            try
            {
                var discovery = await GetDiscoveryDocumentAsync();
                if (discovery == null || string.IsNullOrEmpty(discovery.RevocationEndpoint))
                {
                    Console.WriteLine("No revocation endpoint found or IDP doesn't support it.");
                    _currentAccessToken = null;
                    return;
                }

                var fields = new Dictionary<string, string>
                {
                    { "token", _currentAccessToken },
                    { "token_type_hint", "access_token" },
                    { "client_id", _clientId }
                };

                if (!string.IsNullOrEmpty(_clientSecret))
                {
                    fields["client_secret"] = _clientSecret;
                }

                using var content = new FormUrlEncodedContent(fields);
                var response = await _client.PostAsync(discovery.RevocationEndpoint, content);
                if (!response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Token revocation error: {response.StatusCode} => {body}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Logout error: {ex.Message}");
            }
            finally
            {
                _currentAccessToken = null;
            }
        }

        private async Task<DiscoveryDoc?> GetDiscoveryDocumentAsync()
        {
            try
            {
                var discoUrl = $"{_authority}/.well-known/openid-configuration";
                var resp = await _client.GetAsync(discoUrl);
                if (!resp.IsSuccessStatusCode)
                {
                    var body = await resp.Content.ReadAsStringAsync();
                    Console.WriteLine($"Discovery doc error: {resp.StatusCode} => {body}");
                    return null;
                }

                var json = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                return new DiscoveryDoc
                {
                    TokenEndpoint = doc.RootElement.GetString("token_endpoint"),
                    RevocationEndpoint = doc.RootElement.GetString("revocation_endpoint"),
                    JwksUri = doc.RootElement.GetString("jwks_uri"),
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Discovery doc exception: {ex.Message}");
                return null;
            }
        }

        private class DiscoveryDoc
        {
            public string? TokenEndpoint { get; set; }
            public string? RevocationEndpoint { get; set; }
            public string? JwksUri { get; set; }
        }
    }

    internal static class JsonElementExtensions
    {
        public static string? GetString(this JsonElement element, string propertyName)
        {
            return element.TryGetProperty(propertyName, out var prop)
                ? prop.GetString()
                : null;
        }
    }
}
