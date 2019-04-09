using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Text;
using Undani.Signature.Core.Resource;

namespace Undani.Signature.Core
{
    public class SignFormInstanceHelper : Certificate
    {
        public SignFormInstanceHelper(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey) : base(configuration, user, environmentId, publicKey) { }

        public string Start(Guid formInstanceId)
        {
            string content = "||Formulario:" + formInstanceId.ToString() + "|Firmado:" + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss") + "|Contenido:" + new FormCall(Configuration, User).GetJsonFormInstance(formInstanceId) + "||";

            using (SqlConnection cn = new SqlConnection(Configuration["ConnectionString:Signature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Set_SignStart", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = formInstanceId });
                    cmd.Parameters.Add(new SqlParameter("@EnvironmentId", SqlDbType.UniqueIdentifier) { Value = EnvironmentId });
                    cmd.Parameters.Add(new SqlParameter("@Extension", SqlDbType.VarChar, 5) { Value = "" });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Value = content });                 
                    cmd.Parameters.Add(new SqlParameter("@DateTimeNow", SqlDbType.DateTime) { Value = DateTimeNow });

                    cmd.ExecuteNonQuery();

                    content = (string)cmd.Parameters["@Content"].Value;
                }

            }

            return Convert.ToBase64String(GetHash(content));
        }

        public bool End(Guid formInstanceId, string digitalSignature)
        {
            string content = "";
            using (SqlConnection cn = new SqlConnection(Configuration[""]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Get_DocumentContent", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = formInstanceId });
                    cmd.Parameters.Add(new SqlParameter("@EnvironmentId", SqlDbType.UniqueIdentifier) { Value = EnvironmentId });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    content = (string)cmd.Parameters["@Content"].Value;
                }

            }

            bool valid = false;
            if (ValidateSeal(content, digitalSignature))
            {
                using (SqlConnection cn = new SqlConnection(Configuration[""]))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("usp_Set_SignEnd", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = formInstanceId });
                        cmd.Parameters.Add(new SqlParameter("@EnvironmentId", SqlDbType.UniqueIdentifier) { Value = EnvironmentId });
                        cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = User.Id });
                        cmd.Parameters.Add(new SqlParameter("@SerialNumber", SqlDbType.VarChar, 100) { Value = SerialNumber });
                        cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = Name });
                        cmd.Parameters.Add(new SqlParameter("@RFC", SqlDbType.VarChar, 13) { Value = RFC });
                        cmd.Parameters.Add(new SqlParameter("@CURP", SqlDbType.VarChar, 18) { Value = CURP });
                        cmd.Parameters.Add(new SqlParameter("@DigitalSignature", SqlDbType.VarChar, 1000) { Value = digitalSignature });
                        cmd.Parameters.Add(new SqlParameter("@DateTimeNow", SqlDbType.DateTime) { Value = DateTimeNow });

                        Document document = new Document() { Id = formInstanceId, EnvironmentId = EnvironmentId, ContentSigned = content };
                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                document.Signs.Add(new Sign()
                                {
                                    SerialNumber = reader.GetString(0),
                                    Name = reader.GetString(1),
                                    RFC = reader.GetString(2),
                                    CURP = reader.GetString(3),
                                    DigitalSignature = reader.GetString(4),
                                    Date = reader.GetDateTime(5)
                                });
                            }

                           // return SetFormInstanceSign(formInstance);
                        }
                    }
                }
            }

            return valid;
        }
    }
}
