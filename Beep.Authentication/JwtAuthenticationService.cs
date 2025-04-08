using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

namespace Beep.Authentication
{
    public class JwtAuthenticationService : IAuthenticationService
    {
        private readonly string _secretKey;

        public JwtAuthenticationService(string secretKey)
        {
            _secretKey = secretKey;
        }

        public async Task<string?> AuthenticateAsync(string username, string password)
        {
            // Demo: Here you’d check a DB or external service
            if (username == "test" && password == "password")
            {
                // Generate JWT
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_secretKey);

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, username),
                        new Claim(ClaimTypes.Role, "Admin") // Just an example
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature
                    )
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            // Return null if authentication fails
            return null;
        }

        public async Task<UserInfo?> ValidateTokenAsync(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_secretKey);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // This will check whether the token has expired
                    ValidateLifetime = true
                }, out SecurityToken validatedToken);

                var jwtToken = validatedToken as JwtSecurityToken;
                if (jwtToken == null) return null;

                // Extract claims
                var username = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
                var role = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

                return new UserInfo
                {
                    Username = username,
                    Roles = role != null ? new List<string> { role } : new List<string>()
                };
            }
            catch
            {
                // Token invalid or expired
                return null;
            }
        }

        public async Task LogoutAsync()
        {
            // For purely JWT-based auth, logout might mean clearing local storage or tokens in the client.
            // The library itself doesn’t necessarily store state, so possibly no-op here.
        }
    }
}
