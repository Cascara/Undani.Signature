using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature
{
    public class ActivityInstanceDocumentSigned
    {
        public string SystemName { get; set; }
        public string OriginalName { get; set; }
        public string HashCode { get; set; }
        public bool Created { get; set; }
    }
}
