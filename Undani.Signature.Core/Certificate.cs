using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Dynamic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Undani.JWT;
using Undani.Signature.Core.Resource;

namespace Undani.Signature.Core
{
    public abstract class Certificate
    {
        private IConfiguration _configuration;
        private User _user;
        private Guid _environmentId;
        private byte[] _publicKey;
        private string _number;
        private string _content;
        private string _error = string.Empty;

        private X509Certificate _x509PublicKey;

        private string _curp = "";
        private string _rfc;
        private string _name;
        private DateTime _expirationDate;
        private DateTime _datetimeNow;
        private string _serialNumber;

        public Certificate(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey)
        {
            _configuration = configuration;

            if (user != null)
                _user = user;
            else
                _user = GetAnonymousUser();

            _environmentId = environmentId;

            _publicKey = publicKey;

            _x509PublicKey = new X509Certificate(_publicKey);

            SetCertificateProperties();
        }

        public IConfiguration Configuration
        {
            get { return _configuration; }
        }

        public User User
        {
            get { return _user; }
        }

        public Guid EnvironmentId
        {
            get { return _environmentId; }
        }

        public byte[] PublicKey
        {
            get { return _publicKey; }
        }

        public X509Certificate X509PublicKey
        {
            get { return _x509PublicKey; }
        }

        public string RFC
        {
            get {
                if (_rfc.Contains("/"))
                {
                    return _rfc.Substring(_rfc.IndexOf("/") + 1).Trim();
                }
                else
                    return _rfc;
            }
        }

        public string CURP
        {
            get {
                if (_curp.Contains("/"))
                {
                    return _curp.Replace("/", "").Trim().Replace("\"", "").Trim();
                }
                else
                    return _curp;
            }
        }

        public string Name
        {
            get { return _name; }
        }

        public DateTime ExpirationDate
        {
            get { return _expirationDate; }
        }

        public DateTime DateTimeNow
        {
            get { return _datetimeNow; }
        }

        public string SerialNumber
        {
            get { return _serialNumber; }
        }

        private void SetCertificateProperties()
        {
            string[] attributes = X509PublicKey.Subject.Split(',');

            Dictionary<string, string> result = new Dictionary<string, string>();

            string[] values;
            foreach (string attribute in attributes)
            {
                values = attribute.Split('=');
                result.Add(values[0].Trim(), values[1].Trim());
            }

            if (result.Count == 0)
                throw new Exception("Certificate is wrong");


            _rfc = result["OID.2.5.4.45"];
            if (RFC.Length != 13 && RFC.Length != 12)
                throw new Exception("The rfc number is wrong");

            if (RFC.Length == 13)
            {
                _curp = result["SERIALNUMBER"];
                if (CURP.Length != 18)
                    throw new Exception("The curp number is wrong");
            }

            _name = result["O"];
            if (Name.Length == 0)
                throw new Exception("The name is wrong");

            _expirationDate = DateTime.Parse(X509PublicKey.GetExpirationDateString());

            _datetimeNow = GetDateTimeNow();

            if (ExpirationDate < DateTimeNow && RFC != "MARL8408036H4")
                throw new Exception("The certificate has expired");

            _serialNumber = GetSerialNumber();

        }

        private DateTime GetDateTimeNow()
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Get_DateTimeNow", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@DateTime", SqlDbType.DateTime) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    return (DateTime)cmd.Parameters["@DateTime"].Value;
                }

            }
        }

        private string GetSerialNumber()
        {
            string result = "";

            string publicKeySerialNumber = X509PublicKey.GetSerialNumberString();

            char[] aPublicKeySerialNumber = publicKeySerialNumber.ToCharArray();

            bool flag = false;

            foreach (char val in aPublicKeySerialNumber)
            {
                if (flag)
                {
                    result += val;
                    flag = false;
                }
                else
                    flag = true;
            }

            return result;
        }

        public bool ValidateRevocation()
        {
            ///TODO: Hacer la validacion de forma asincrona
            return true;
        }

        public byte[] GetHash(string text)
        {
            SHA256Managed sha256 = new SHA256Managed();

            UnicodeEncoding encoding = new UnicodeEncoding();

            byte[] data = encoding.GetBytes(text);

            byte[] hash = sha256.ComputeHash(data);

            return hash;
        }

        public bool ValidateSeal(string content, string digitalSignature)
        {
            X509Certificate2 cert = new X509Certificate2(PublicKey);

            RSA csp = (RSA)cert.PublicKey.Key;

            byte[] hash = GetHash(content);

            bool esValida = csp.VerifyHash(hash, Convert.FromBase64String(digitalSignature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return esValida;
        }

        public string PublicKeySerialNumber(string publicKeySerialNumber)
        {
            string result = "";

            char[] aPublicKeySerialNumber = publicKeySerialNumber.ToCharArray();

            bool flag = false;

            foreach (char val in aPublicKeySerialNumber)
            {
                if (flag)
                {
                    result += val;
                    flag = false;
                }
                else
                {
                    flag = true;
                }
            }

            return result;
        }

        public string GetCrc32(string text)
        {
            Crc32 crc32 = new Crc32();

            String hash = String.Empty;

            foreach (byte b in crc32.ComputeHash(Encoding.ASCII.GetBytes(text))) hash += b.ToString("x2").ToLower();

            return hash.ToUpper();
        }

        private User GetAnonymousUser()
        {

            dynamic userAnonymous = JsonConvert.DeserializeObject<ExpandoObject>(Configuration["DataAnonymous"], new ExpandoObjectConverter());

            var claims = new List<Claim>();

            claims.Add(new Claim(ClaimTypes.Name, userAnonymous.Name));
            claims.Add(new Claim(ClaimTypes.NameIdentifier, userAnonymous.NameIdentifier));
            claims.Add(new Claim(ClaimTypes.Email, userAnonymous.Email));
            claims.Add(new Claim(ClaimTypes.GroupSid, userAnonymous.Email));

            var _Identity = new ClaimsIdentity(claims, "Basic");

            return new User() { Id = Guid.Parse(userAnonymous.NameIdentifier), Name = userAnonymous.Name, Token = JWToken.Token(_Identity) };

        }
    }
}
