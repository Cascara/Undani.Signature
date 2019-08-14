using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Text;
using Undani.Signature.Core.Infra;
using Undani.Signature.Core.Resource;

namespace Undani.Signature.Core
{
    public class UserHelper
    {
        private IConfiguration _configuration;
        private User _user;

        public UserHelper(IConfiguration configuration, User user)
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
            get {
                using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("usp_Get_User", cn))
                    {

                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = _user.Id });
                        cmd.Parameters.Add(new SqlParameter("@RFC", SqlDbType.VarChar, 13) { Direction = ParameterDirection.Output });

                        cmd.ExecuteNonQuery();

                        _user.RFC = (string)cmd.Parameters["@RFC"].Value;
                    }
                }

                return _user;
            }
        }

        public string GetPassword(string userName, string contentFactorAuthentication)
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Get_UserPassword", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@UserName", SqlDbType.VarChar, 13) { Value = userName });
                    cmd.Parameters.Add(new SqlParameter("@ContentFactorAuthentication", SqlDbType.VarChar, 2000) { Value = contentFactorAuthentication });
                    cmd.Parameters.Add(new SqlParameter("@Password", SqlDbType.VarChar, 250) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    return (string)cmd.Parameters["@Password"].Value;
                }
            }
        }

        public _UserLogin CreateUser(Guid ownerId, string rfc, string userName, string name, string content, string contentFactorAuthentication, string password)
        {
            _UserIdentity _userIdentity = new IdentityCall(Configuration, _user).CreateUser(ownerId, name, rfc, password);

            TrackingCall trackingCall = new TrackingCall(Configuration, _user);
            trackingCall.CreateUser(_userIdentity.SubjectId, ownerId, _userIdentity.Name, _userIdentity.GivenName, _userIdentity.FamilyName, _userIdentity.Email, rfc, content);

            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Create_User", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = _userIdentity.SubjectId });
                    cmd.Parameters.Add(new SqlParameter("@UserName", SqlDbType.VarChar, 100) { Value = userName });
                    cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = name });
                    cmd.Parameters.Add(new SqlParameter("@RFC", SqlDbType.VarChar, 13) { Value = rfc });
                    cmd.Parameters.Add(new SqlParameter("@Password", SqlDbType.VarChar, 250) { Value = password });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, 2000) { Value = content });
                    cmd.Parameters.Add(new SqlParameter("@ContentFactorAuthentication", SqlDbType.VarChar, 1000) { Value = contentFactorAuthentication });

                    cmd.ExecuteNonQuery();
                }
            }

            return new _UserLogin() { UserName = userName, Password = password };
        }
    }
}
