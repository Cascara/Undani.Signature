using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Text;

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
    }
}
