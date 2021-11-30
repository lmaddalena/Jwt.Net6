using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using IdentityManager.Models;

namespace IdentityManager.Controllers
{

    [Route("Api/[controller]")]
    public class TokenProviderController : Controller
    {
        private readonly ILogger _logger;
        private Services.ITokenService _tokenService;

        // costructor
        public TokenProviderController(ILogger<TokenProviderController> logger, Services.ITokenService tokenService)
        {
            _logger = logger;
            _tokenService = tokenService;
        }

       // GET api/tokenprovider/username/password
        [HttpGet("{username}/{password}")]
        public async Task<IActionResult> Get(string username, string password)
        {
            _logger.LogInformation(0, "Get token for username: {0}", username);

            if(!ModelState.IsValid)
                return BadRequest(ModelState);

            string token = await _tokenService.GenerateTokenAsync(username, password);

            if(!string.IsNullOrEmpty(token))
                return this.Ok(token);
            else
                return this.Unauthorized("Invalid username or password");
                        
        }

        /// <summary>
        /// Creates new Authorization Token
        /// </summary>
        /// <param name="model">LoginModel parameter</param>
        /// <returns>A newly created Token</returns>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /Api/TokenProvider
        ///     {
        ///        "username: "TEST",
        ///        "password": "TEST123",
        ///     }
        ///
        /// </remarks>
        /// <response code="201">Returns the newly created Token</response>
        /// <response code="401">If the username or password are incorrect</response>
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Post([FromBody]LoginModel model)
        {
            _logger.LogInformation(0, "Get token for username: {0}", model.Username);

            if(!ModelState.IsValid)
                return BadRequest(ModelState);

            string token = await _tokenService.GenerateTokenAsync(model.Username, model.Password);

            if(!string.IsNullOrEmpty(token))
                return this.Ok(token);
            else
                return this.Unauthorized("Invalid username or password");
                        
        }

    }

}
