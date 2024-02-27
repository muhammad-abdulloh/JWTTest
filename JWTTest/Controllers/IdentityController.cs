using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTTest.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login( string username, string password)
        {
            if (username == "olaaa" && password == "12345")
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username)
                };

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.AddSeconds(70),
                    SigningCredentials = new SigningCredentials(GetSignedKey(), SecurityAlgorithms.HmacSha256Signature)
                }; 
                

                var tokenHandler  = new JwtSecurityTokenHandler();
                var securityToken  = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(securityToken);
                return Ok(new { token = tokenString });

            }
            return Ok("davay");
        }

        private SymmetricSecurityKey GetSignedKey()
        {
            var secret = Encoding.ASCII.GetBytes("luboySexredtDLKJBFBEJBJKearg43wt524y4yw45ybw54wbq3t4wt45y45wyq45yy");
            return new SymmetricSecurityKey(secret);
        }

        [Authorize]
        [HttpGet("protected-data")]
        public IActionResult GetProtectedData()
        {
            // Access protected data here
            return Ok(new { message = "This data is protected!" });
        }

    }
}
