using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Beep.Authentication
{
    public class AzureAdAuthenticationService : IAuthenticationService
    {
        private readonly string _clientId;
        private readonly string _tenantId;
        private readonly string[] _scopes; // e.g. Graph scopes or custom 
        private IPublicClientApplication? _app;

        public AzureAdAuthenticationService(string clientId, string tenantId, string[] scopes)
        {
            _clientId = clientId;
            _tenantId = tenantId;
            _scopes = scopes;
        }

        private IPublicClientApplication BuildApp()
        {
            if (_app == null)
            {
                _app = PublicClientApplicationBuilder.Create(_clientId)
                    .WithAuthority(AzureCloudInstance.AzurePublic, _tenantId)
                    .WithDefaultRedirectUri()  // For desktop, might use a custom redirect URI
                    .Build();
            }
            return _app;
        }

        public async Task<string?> AuthenticateAsync(string username, string password)
        {
            // Typically, for Azure AD, username/password flow is discouraged in public client apps.
            // More common is interactive or device code flow.
            // Here's a simple device code flow as an example:

            var app = BuildApp();
            try
            {
                var result = await app.AcquireTokenWithDeviceCode(_scopes, async codeResult =>
                {
                    // You could display the device code instructions
                    Console.WriteLine(codeResult.Message);
                }).ExecuteAsync();

                return result.AccessToken;  // Return the token
            }
            catch (MsalServiceException ex)
            {
                // handle errors (e.g. canceled, no network, invalid_client, etc.)
                Console.WriteLine($"MSAL Service Exception: {ex.Message}");
                return null;
            }
            catch (MsalClientException ex)
            {
                // handle client errors
                Console.WriteLine($"MSAL Client Exception: {ex.Message}");
                return null;
            }
        }

        public async Task<UserInfo?> ValidateTokenAsync(string token)
        {
            // With MSAL, we typically validate the token by calling MS Graph or 
            // ensuring it’s not expired (MSAL does that for you behind the scenes).
            // For demonstration, we might parse basic claims from the token:

            if (string.IsNullOrEmpty(token))
                return null;

            // This is a simplistic approach—real validation uses libraries 
            // to parse and validate JWT properly.
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
                return null;

            var jwt = handler.ReadJwtToken(token);
            var username = jwt.Claims.FirstOrDefault(c => c.Type == "unique_name")?.Value
                           ?? jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
            var userId = jwt.Claims.FirstOrDefault(c => c.Type == "oid")?.Value;  // object ID in AAD

            // Return your user info
            return new UserInfo
            {
                UserId = userId,
                Username = username
            };
        }

        public async Task LogoutAsync()
        {
            // Typically in MSAL, to sign out, you remove accounts from the cache.
            // For device code flow, you can remove the local account from MSAL’s token cache:

            var app = BuildApp();
            var accounts = await app.GetAccountsAsync();
            foreach (var acct in accounts)
            {
                await app.RemoveAsync(acct);
            }
        }
    }
}
