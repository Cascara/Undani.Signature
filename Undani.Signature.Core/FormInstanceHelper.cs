using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature.Core
{
    public class FormInstanceHelper : Certificate
    {
        public FormInstanceHelper(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey) : base(configuration, user, environmentId, publicKey) { }

        public void StartSignature(Guid formInstance)
        {

        }
    }
}
