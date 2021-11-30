using System;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace IdentityManager.Services
{
    public class TokenService : ITokenService
    {
        private readonly ILogger _logger;
        private Respository.IUserRepository _userRepository;
        private readonly IConfiguration _configuration;

        public TokenService(ILogger<TokenService> logger, IConfiguration configuration, Respository.IUserRepository userRepository)
        {
            _logger = logger;
            _userRepository = userRepository;   
            _configuration = configuration;
        }
        public async Task<string> GenerateTokenAsync(string username, string password)
        {
            var identity = await GetIdentityAsync(username, password);

            if (identity == null || !identity.IsAuthenticated)
            {
                return "";
            }


            // get the secret passphrase from config
            string secretKey = _configuration.GetSection("TokenAuthentication:SecretKey").Value;

            // create the symmetrical key to sign and validate JWTs
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));            
            TokenProviderOptions options = new TokenProviderOptions()
            {
                Audience = _configuration.GetSection("TokenAuthentication:Audience").Value,
                Issuer = _configuration.GetSection("TokenAuthentication:Issuer").Value,
                Expiration = TimeSpan.FromMinutes(30),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)

            }; 
            var now = DateTime.UtcNow;

            // ToUnixTimeSeconds() avaliable from .NET 4.6
            // (number of seconds from 1970/1/1)
            //var unixDateTime = now.ToUnixTimeSeconds()

            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var unixDateTime = (now - epoch).TotalSeconds;

            // Specifically add the jti (random nonce), iat (issued timestamp), and sub (subject/user) claims.
            // You can add other claims here, if you want:
            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Name, username),
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, unixDateTime.ToString(), ClaimValueTypes.Integer),
                new Claim(ClaimTypes.Role, "Guest"),
                new Claim(ClaimTypes.Role, "Foo"),
                new Claim("Stanza", "123")
            };

            // create a new JWT token and write it to a string
            var jwt = new JwtSecurityToken(
                issuer: options.Issuer,
                audience: options.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(options.Expiration),
                signingCredentials: options.SigningCredentials
            );

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var token = new
            {
                access_token = encodedJwt,
                expires_in = (int)options.Expiration.TotalSeconds
            };

            // serialize and return the token
            string s_token = JsonConvert.SerializeObject(token, new JsonSerializerSettings { Formatting = Formatting.Indented });
            return s_token;
        }

        public async Task<ClaimsIdentity> GetIdentityAsync(string username, string password)
        {

            bool isLoggedIn = await _userRepository.LogInAsync(username, password);

            ClaimsIdentity claimsIdentity;
            
            if(isLoggedIn)
            {
                claimsIdentity = new ClaimsIdentity(
                        new System.Security.Principal.GenericIdentity(username, "Token"), 
                        new Claim[]{}
                    );


            }
            else
            {
                claimsIdentity = new ClaimsIdentity(
                        null,
                        new Claim[]{}
                    );

            }

            return claimsIdentity;



        }
    }

}