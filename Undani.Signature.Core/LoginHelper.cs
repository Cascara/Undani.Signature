using Microsoft.Extensions.Configuration;
using System;
using Undani.Signature.Core.Infra;

namespace Undani.Signature.Core
{
    public class LoginHelper : Certificate
    {
        public LoginHelper(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey) : base(configuration, user, environmentId, publicKey) { }

        public string Start()
        {
            string signNumber = "||SignNumber:" + GetCrc32(DateTimeNow.ToString("dd/MM/yyyy")) + SerialNumber + "||";

            return Convert.ToBase64String(GetHash(signNumber));
        }

        public _UserLogin End(Guid ownerId, string digitalSignature, string content)
        {
            string signNumber = "||SignNumber:" + GetCrc32(DateTimeNow.ToString("dd/MM/yyyy")) + SerialNumber + "||";

            if (ValidateSeal(signNumber, digitalSignature))
            {
                UserHelper userHelper = new UserHelper(Configuration, User);

                string password = userHelper.GetPassword(RFC, content);

                if (password == "")
                {
                    password = GetCrc32(RFC + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss"));

                    return userHelper.CreateUser(ownerId, RFC, Name, content, password);
                }
                else
                {
                    return new _UserLogin() { UserName = RFC, Password = password };
                }
            }

            throw new Exception("The access is invalid");
        }
    }
}
