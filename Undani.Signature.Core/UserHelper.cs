using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Dynamic;
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
                        cmd.Parameters.Add(new SqlParameter("@Reference", SqlDbType.VarChar, 50) { Direction = ParameterDirection.Output });

                        cmd.ExecuteNonQuery();

                        _user.Reference = (string)cmd.Parameters["@Reference"].Value;
                    }
                }

                return _user;
            }
        }

        public string GetPassword(string userName,string contentFactorAuthentication, ref Guid userId)
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Get_UserPassword", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@UserName", SqlDbType.VarChar, 100) { Value = userName });
                    cmd.Parameters.Add(new SqlParameter("@ContentFactorAuthentication", SqlDbType.VarChar, 1000) { Value = contentFactorAuthentication });
                    cmd.Parameters.Add(new SqlParameter("@Password", SqlDbType.VarChar, 250) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    userId = (Guid)cmd.Parameters["@UserId"].Value;

                    return (string)cmd.Parameters["@Password"].Value;
                }
            }
        }

        public _UserLogin CreateUser(Guid ownerId, string roles, string reference, string userName, string name, string content, string contentFactorAuthentication, string password)
        {
            _UserIdentity _userIdentity = new IdentityCall(Configuration, _user).CreateUser(ownerId, name, reference, password);

            TrackingCall trackingCall = new TrackingCall(Configuration, _user);
            trackingCall.CreateUser(_userIdentity.SubjectId, ownerId, reference, roles, reference, _userIdentity.GivenName, _userIdentity.FamilyName, _userIdentity.Email, content);

            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Create_User", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = _userIdentity.SubjectId });
                    cmd.Parameters.Add(new SqlParameter("@UserName", SqlDbType.VarChar, 100) { Value = userName });
                    cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = name });
                    cmd.Parameters.Add(new SqlParameter("@Reference", SqlDbType.VarChar, 50) { Value = reference });
                    cmd.Parameters.Add(new SqlParameter("@Password", SqlDbType.VarChar, 250) { Value = password });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, 2000) { Value = content });
                    cmd.Parameters.Add(new SqlParameter("@ContentFactorAuthentication", SqlDbType.VarChar, 1000) { Value = contentFactorAuthentication });

                    cmd.ExecuteNonQuery();
                }
            }

            return new _UserLogin() { UserName = userName, Password = password };
        }

        public void SetContent(Guid userId, string content)
        {
            TrackingCall trackingCall = new TrackingCall(Configuration, _user);
            trackingCall.SetContent(userId, content);

            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Set_UserContent", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = userId });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, 2000) { Value = content });

                    cmd.ExecuteNonQuery();
                }
            }
        }

        public bool ContentExists(Guid ownerId, string content)
        {
            JObject oJson = JObject.Parse(content);

            Owner owner = LoginHelper.GetOwner(Configuration, ownerId);

            if (owner.ContentFactorAuthentication != string.Empty)
            {
                dynamic contentFactorAuthentication = JsonConvert.DeserializeObject<ExpandoObject>(owner.ContentFactorAuthentication, new ExpandoObjectConverter());

                IDictionary<string, object> dicContentFactorAuthentication = contentFactorAuthentication;

                foreach (string key in dicContentFactorAuthentication.Keys)
                {
                    owner.ContentFactorAuthentication = owner.ContentFactorAuthentication.Replace((string)dicContentFactorAuthentication[key], (string)oJson.SelectToken(dicContentFactorAuthentication[key].ToString().Replace("[", "").Replace("]", "")));
                }
            }

            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Get_UserContentFactorAuthenticationExists", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ContentFactorAuthentication", SqlDbType.VarChar, 1000) { Value = owner.ContentFactorAuthentication });
                    cmd.Parameters.Add(new SqlParameter("@Exists", SqlDbType.Bit) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    return (bool)cmd.Parameters["@Exists"].Value;
                }
            }
        }
    }
}
