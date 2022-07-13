using JwtAuthntication.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JwtAuthntication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
                                        RoleManager<IdentityRole> roleManager,
                                        IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody]LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.UserName);
            if(user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var userRole = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                foreach(var item in userRole)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, item));
                }

                var token = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });

            }
            return Unauthorized();

        }

        private JwtSecurityToken GetToken(List<Claim> claims)
        {
            var authKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: claims,
                signingCredentials: new SigningCredentials(authKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            var userNameExists = await _userManager.FindByNameAsync(registerModel.UserName);
            var userEmailExists = await _userManager.FindByEmailAsync(registerModel.Email);
            if (userNameExists != null || userEmailExists != null)
                return StatusCode(StatusCodes.Status406NotAcceptable, new ResponseModel { Status = "Error", Message = "User already exists" });

            IdentityUser user = new IdentityUser
            {
                Email = registerModel.Email,
                UserName = registerModel.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(user, registerModel.Password);
            if (result.Succeeded)
            {
                if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

                await _userManager.AddToRoleAsync(user, UserRoles.User);
                //return Ok(new ResponseModel { Status = "Success", Message = "User created" });
                return StatusCode(StatusCodes.Status201Created, new ResponseModel { Status = "Success", Message = "User created" });
            }
               

            return StatusCode(StatusCodes.Status400BadRequest, new ResponseModel { Status = "Error", Message = "an error has occured" });
        }

        [HttpPost]
        [Route("adminregister")]
        public async Task<IActionResult> AdminRegister([FromBody] RegisterModel registerModel)
        {
            var userNameExists = await _userManager.FindByNameAsync(registerModel.UserName);
            var userEmailExists = await _userManager.FindByEmailAsync(registerModel.Email);
            if (userNameExists != null || userEmailExists != null)
                return StatusCode(StatusCodes.Status406NotAcceptable, new ResponseModel { Status = "Error", Message = "User already exists" });

            IdentityUser user = new IdentityUser
            {
                Email = registerModel.Email,
                UserName = registerModel.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(user, registerModel.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status400BadRequest, new ResponseModel { Status = "Error", Message = "an error has occured" });

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));

            await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            return StatusCode(StatusCodes.Status201Created, new ResponseModel { Status = "Success", Message = "User created" });
        }




    }
}
