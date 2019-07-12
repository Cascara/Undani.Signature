using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Text;

namespace Undani.Signature.Core
{
    public class DocumentHelper
    {
        private IConfiguration _configuration;
        private User _user;

        public DocumentHelper(IConfiguration configuration, User user)
        {
            _configuration = configuration;
            _user = user;
        }

        public IConfiguration Configuration
        {
            get { return _configuration; }
        }

        public string GetContent(string key, Guid formInstanceId)
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Get_FormInstanceDocumentContent", cn) { CommandType = CommandType.StoredProcedure })
                {
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                    cmd.Parameters.Add(new SqlParameter("@FormInstanceId", SqlDbType.UniqueIdentifier) { Value = formInstanceId });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    return (string)cmd.Parameters["@Content"].Value;
                }

            }
        }
    }
}
