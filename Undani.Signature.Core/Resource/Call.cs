using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature.Core.Resource
{
    internal abstract class Call
    {
        private IConfiguration _configuration;
        private User _user;

        public Call(IConfiguration configuration, User user)
        {
            _configuration = configuration;
            _user = user;
        }

        public IConfiguration Configuration
        {
            get { return _configuration; }
        }

        public User User
        {
            get { return _user; }
        }
    }
}
