using Microsoft.Data.SqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Text;

namespace Undani.Signature
{
    public class SignatureException : Exception
    {
        public SignatureException()
        {

        }

        public SignatureException(string message, string cnStr) : base(message)
        {
            using (SqlConnection cn = new SqlConnection(cnStr))
            {
                cn.Open();
                using (SqlCommand cmd = new SqlCommand("usp_Set_Exception", cn))
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