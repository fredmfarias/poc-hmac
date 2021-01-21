using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PocHmacServer.Models;
using System.Collections.Generic;

namespace PocHmacServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = "api")]
    public class ValuesController : ControllerBase
    {
        [HttpGet]
        public IEnumerable<string> Get() => new[] { "value1", "value2" };

        [HttpPost]
        public void Post([FromBody] Foo foo)
        {
        }
    }
}
