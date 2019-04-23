using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Undani.Signature.Test.Controllers
{

    public class TestController : Controller
    {
        private IConfiguration _configuration;

        public TestController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IActionResult EFirmaLogin()
        {
            ViewBag.Configuration = _configuration;

            return View();
        }
    }
}