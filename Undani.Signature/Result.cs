using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature
{
    public class Result
    {
        public Result()
        {
            Error = "";
        }
        public object Value { get; set; }
        public string Error { get; set; }
    }
}
