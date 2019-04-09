using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature
{
    public class Sign
    {
        public string SerialNumber { get; set; }
        public string Name { get; set; }
        public string RFC { get; set; }
        public string CURP { get; set; }
        public string DigitalSignature { get; set; }
        public DateTime Date { get; set; }
    }
}
