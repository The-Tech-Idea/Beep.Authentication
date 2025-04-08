using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;


namespace Beep.Authentication
{
    public class WindowsDomainAuthenticationService : IAuthenticationService
    {
        private readonly string _domainName;

        public WindowsDomainAuthenticationService(string domainName)
        {
            _domainName = domainName;
        }

        public async Task<string?> AuthenticateAsync(string username, string password)
        {
            // Because this is a blocking call, you might wrap it in Task.Run for async usage.
            return await Task.Run(() =>
            {
                try
                {
                    // "using" will dispose of the context after usage
                    using (var pc = new PrincipalContext(ContextType.Domain, _domainName))
                    {
                        // Validate user credentials
                        bool isValid = pc.ValidateCredentials(username, password);
                        if (isValid)
                        {
                            // If valid, you might return some token or an indication of success.
                            // For domain auth, there's typically no "JWT" by default.
                            // You might create your own custom token or just return a success marker.
                            return Guid.NewGuid().ToString();
                        }
                    }
                }
                catch
                {
                    // handle or log exceptions (e.g., domain unreachable, etc.)
                }
                return null;
            });
        }

        public async Task<UserInfo?> ValidateTokenAsync(string token)
        {
            // In a pure domain scenario, there's no built-in "token" from AD 
            // unless you’re also integrating with Kerberos tickets or external SSO.
            // This method might not be used (or you craft your own approach).

            // For demonstration, we’ll return null to show that "token" isn't used here.
            await Task.CompletedTask;
            return null;
        }

        public async Task LogoutAsync()
        {
            // Typically, domain auth doesn't have a direct "logout" from a domain
            // The client can simply discard any local tokens/credentials.
            await Task.CompletedTask;
        }
    }
}
