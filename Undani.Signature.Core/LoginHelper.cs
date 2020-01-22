using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Dynamic;
using Undani.Signature.Core.Infra;

namespace Undani.Signature.Core
{
    public class LoginHelper : Certificate
    {
        public LoginHelper(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey) : base(configuration, user, environmentId, publicKey) { }

        public string Start()
        {
            ValidateRevocation();

            string content = "";

            string signNumber = "||SignNumber:" + GetCrc32(DateTimeNow.ToString("dd/MM/yyyy")) + SerialNumber + "||";

            content = Convert.ToBase64String(GetHash(signNumber));

            return content;
        }

        public _UserLogin End(Guid ownerId, string digitalSignature, string content)
        {

            JObject oJson = JObject.Parse(content);

            Owner owner = GetOwner(Configuration, ownerId);

            if (owner.Signatory != string.Empty)
            {
                JToken jToken = oJson.SelectToken(owner.Signatory);
                ValidateSignatory((string)jToken);
            }

            if (owner.ContentFactorAuthentication != string.Empty)
            {
                dynamic contentFactorAuthentication = JsonConvert.DeserializeObject<ExpandoObject>(owner.ContentFactorAuthentication, new ExpandoObjectConverter());

                IDictionary<string, object> dicContentFactorAuthentication = contentFactorAuthentication;

                foreach (string key in dicContentFactorAuthentication.Keys)
                {
                    owner.ContentFactorAuthentication = owner.ContentFactorAuthentication.Replace((string)dicContentFactorAuthentication[key], (string)oJson.SelectToken(dicContentFactorAuthentication[key].ToString().Replace("[[", "").Replace("]]", "")));
                }
            }


            string signNumber = "||SignNumber:" + GetCrc32(DateTimeNow.ToString("dd/MM/yyyy")) + SerialNumber + "||";

            if (ValidateSeal(signNumber, digitalSignature))
            {
                UserHelper userHelper = new UserHelper(Configuration, User);

                Guid userId = Guid.Empty;

                string password = userHelper.GetPassword(Reference, owner.ContentFactorAuthentication, ref userId);

                if (password == "")
                {
                    password = GetCrc32(Reference + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss"));

                    return userHelper.CreateUser(ownerId, owner.Roles, Reference, Reference, Name, content, owner.ContentFactorAuthentication, password);
                }
                else
                {
                    userHelper.SetContent(userId, content);

                    return new _UserLogin() { UserName = Reference, Password = password };
                }
            }

            throw new Exception("S503");
        }

        public static Owner GetOwner(IConfiguration configuration, Guid ownerId)
        {
            using (SqlConnection cn = new SqlConnection(configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Get_Owner", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@OwnerId", SqlDbType.UniqueIdentifier) { Value = ownerId });
                    cmd.Parameters.Add(new SqlParameter("@Signatory", SqlDbType.VarChar, 1000) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@ContentFactorAuthentication", SqlDbType.VarChar, 1000) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@Roles", SqlDbType.VarChar, 1000) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    return new Owner()
                    {
                        Signatory = (string)cmd.Parameters["@Signatory"].Value,
                        ContentFactorAuthentication = (string)cmd.Parameters["@ContentFactorAuthentication"].Value,
                        Roles = (string)cmd.Parameters["@Roles"].Value
                    };
                }
            }
        }
    }
}
