using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature
{
    public class Owner
    {
        public string Signatory { get; set; }
        public string ContentFactorAuthentication { get; set; }
        public string ContentFactorAuthenticationUserName { get; set; }
        public string Roles { get; set; }
    }
}
