using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature
{
    public class ElementSignature
    {
        public string ElementId { get; set; }
        public string Template { get; set; }
        public string Key { get; set; }
        public List<string> JsonPaths { get; set; }
        public int ElementSignatureTypeId { get; set; }
        public string Content { get; set; }
        public string OriginalName { get; set; }
        public bool Create { get; set; }
    }
}
