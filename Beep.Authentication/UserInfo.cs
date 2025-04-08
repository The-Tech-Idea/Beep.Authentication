using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Beep.Authentication
{
    public class UserInfo
    {
        public string? UserId { get; set; }
        public string? Username { get; set; }
        public List<string>? Roles { get; set; }
        public Dictionary<string, string>? AdditionalClaims { get; set; }
        // Add more properties as necessary
    }
}
