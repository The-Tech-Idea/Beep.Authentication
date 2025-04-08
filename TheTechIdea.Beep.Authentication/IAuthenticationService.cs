using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TheTechIdea.Beep.Authentication
{
    public interface IAuthenticationService
    {
        /// <summary>
        /// Validates user credentials and returns an auth token if successful.
        /// </summary>
        /// <param name="username">User name</param>
        /// <param name="password">Password</param>
        /// <returns>Token or null if invalid</returns>
        Task<string?> AuthenticateAsync(string username, string password);

        /// <summary>
        /// Validates the token and returns user claims or info if valid.
        /// </summary>
        /// <param name="token">JWT or custom token</param>
        /// <returns>Information about the user or null if invalid</returns>
        Task<UserInfo?> ValidateTokenAsync(string token);

        /// <summary>
        /// Logs out the current user, if relevant.
        /// </summary>
        Task LogoutAsync();
    }
}
