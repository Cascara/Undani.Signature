using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

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

        private string _curp;
        private string _rfc;
        private string _name;
        private DateTime _expirationDate;

        public Certificate(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey)
        {
            _configuration = configuration;
            _user = user;
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

        public string CURP
        {
            get {
                if (_curp.Contains("/"))
                {
                    return _curp.Replace("/", "").Trim();
                }
                else
                    return _curp;
            }
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

        public string Name
        {
            get { return _name; }
        }

        public DateTime ExpirationDate
        {
            get { return _expirationDate; }
        }

        public Result Result
        {
            get {
                if (_error == "")
                    return new Result() { Number = _number, Content = _content, Error = "" };
                else
                    return new Result() { Number = "", Content = "", Error = _error };
            }
        }

        private void Validate()
        {

            

            Dictionary<string, string> content = GetCertificateContent(_x509PublicKey);

            result.Error = ValidateKey(ref result, uid, content["SERIALNUMBER"], content["O"]);

            result.Error = ValidateExpiration(ref result, content["EXPIRATIONDATE"]);

            result.Error = ValidateOCSP(ref result, publicKeyBytes);
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

            _curp = result["SERIALNUMBER"];            

            if (CURP.Length != 18)
                throw new Exception("The curp number is wrong");

            _rfc = result["2.5.4.45"];
            if (RFC.Length != 13)
                throw new Exception("The rfc number is wrong");
            
            _name = result["O"];
            if (Name.Length == 0)
                throw new Exception("The name is wrong");

            _expirationDate = DateTime.Parse(X509PublicKey.GetExpirationDateString());
            if (ExpirationDate < DateTime.Now)
                throw new Exception("The certificate has expired");

        }
    }
}
