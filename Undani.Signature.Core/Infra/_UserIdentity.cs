using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature.Core.Infra
{
    public class _UserIdentity
    {
        public Guid SubjectId { get; set; }
        public string Email { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string GivenName { get; set; }
        public string Name { get; set; }
        public string FamilyName { get; set; }
        public string Reference { get; set; }
        public Guid OwnerId { get; set; }
    }
}
