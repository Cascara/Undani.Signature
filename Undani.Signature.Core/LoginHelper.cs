using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Text;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Undani.Signature.Core.Infra;
using Undani.Signature.Core.Resource;

namespace Undani.Signature.Core
{
    public class LoginHelper : Certificate
    {
        public LoginHelper(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey) : base(configuration, user, environmentId, publicKey) { }

        public string Start()
        {
            string signNumber = "||SignNumber:" + GetCrc32(DateTimeNow.ToString("dd/MM/yyyy")) +  SerialNumber + "||";

            return Convert.ToBase64String(GetHash(signNumber));
        }

        public _UserLogin End(Guid ownerId, string digitalSignature, string content)
        {
            string signNumber = "||SignNumber:" + GetCrc32(DateTimeNow.ToString("dd/MM/yyyy")) + SerialNumber + "||";

            _UserLogin _userLogin = new _UserLogin();
            if (ValidateSeal(signNumber, digitalSignature))
            {
                string password = GetCrc32(RFC + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss"));

                using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("usp_Create_User", cn))
                    {

                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add(new SqlParameter("@RFC", SqlDbType.VarChar, 13) { Value = RFC });
                        cmd.Parameters.Add(new SqlParameter("@UserName", SqlDbType.VarChar, 100) { Value = Name });
                        cmd.Parameters.Add(new SqlParameter("@Password", SqlDbType.VarChar, 250) { Direction = ParameterDirection.InputOutput, Value = password });
                        cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, 2000) { Value = content });

                        cmd.ExecuteNonQuery();

                        _userLogin.UserName = RFC;
                        _userLogin.Password = (string)cmd.Parameters["@Password"].Value;
                    }
                }

                if (password == _userLogin.Password)
                {
                    _UserIdentity _userIdentity = new IdentityCall(Configuration, User).CreateUser(ownerId, Name, RFC, password);

                    TrackingCall trackingCall = new TrackingCall(Configuration, User);

                    trackingCall.CreateUser(_userIdentity.SubjectId, ownerId, _userIdentity.Name, _userIdentity.GivenName, _userIdentity.FamilyName, _userIdentity.Email, RFC, content);
                }
            }

            return _userLogin;
        }
    }
}
