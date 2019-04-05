using Microsoft.Extensions.Configuration;
using System;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Undani.Signature.Core.Revocation
{
    public partial class ValidationInvoke
    {
        private IConfiguration _configuration;
        private User _user;

        public ValidationInvoke(IConfiguration configuration, User user)
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
        public bool Invoke(Guid systemActionInstanceId, string method, X509Certificate x509PublicKey)
        {
            MethodInfo methodInfo = typeof(ValidationInvoke).GetMethod(method);

            if (methodInfo.IsStatic)
                throw new Exception("The method can not be static");
            else
                return Convert.ToBoolean(methodInfo.Invoke(this, new object[] { systemActionInstanceId, x509PublicKey }));
        }
    }
}
