using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Text;

namespace Undani.Signature.Core
{
    public class FormHelper
    {
        private IConfiguration _configuration;
        private User _user;

        public FormHelper(IConfiguration configuration, User user)
        {
            _configuration = configuration;
            _user = user;
        }

        public IConfiguration Configuration
        {
            get { return _configuration; }
        }

        public string GetJasonPathReference(string elementId)
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Get_ElementSignatory", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ElementId", SqlDbType.VarChar, 50) { Value = elementId });
                    cmd.Parameters.Add(new SqlParameter("@JsonPath", SqlDbType.VarChar, 500) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    return (string)cmd.Parameters["@JsonPath"].Value;
                }
            }
        }

        public List<string> GetJsonPathDocuments(Guid formId)
        {
            List<string> jsonPathDocuments = new List<string>();
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Get_FormJsonPathDocuments", cn))
                {

                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = formId });

                    cmd.ExecuteNonQuery();

                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            jsonPathDocuments.Add(reader.GetString(0));
                        }
                    }
                }
            }

            return jsonPathDocuments;
        }
    }
}
