using JwtAuthntication.Authentication;
using JwtAuthntication.Authentication.Email;
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
        private readonly IEmailSender _emailSender;


        public AuthenticationController(UserManager<IdentityUser> userManager,
                                        RoleManager<IdentityRole> roleManager,
                                        IConfiguration configuration,
                                        IEmailSender emailSender)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailSender = emailSender;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody]LoginModel loginModel)
        {
            //IdentityUser user = await _userManager.FindByNameAsync(loginModel.UserName);
            IdentityUser user = await _userManager.FindByEmailAsync(loginModel.UserName);
            //IdentityUser user = await _userManager.FindByLoginAsync(loginModel.UserName);
            //IdentityUser user = await _userManager.FindByIdAsync(loginModel.UserName);
            
            
            if(user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var userRole = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, "user email"),
                    new Claim(ClaimTypes.MobilePhone, user.PhoneNumber),
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


        /// <summary>
        /// the password should contains capital, small letters, numbers and special char 
        /// </summary>
        /// <param name="registerModel"></param>
        /// <returns></returns>
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
                if (!await _roleManager.RoleExistsAsync("User"))
                    await _roleManager.CreateAsync(new IdentityRole("User"));

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

        [HttpPost]
        [Route("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody] EmailResetPasswordModel model)
        {
            var userNameExists = await _userManager.FindByNameAsync(model.UserName);
            if(userNameExists != null)
            {
                var result = await _userManager.ResetPasswordAsync(userNameExists, model.token, model.Password);

                if (!result.Succeeded)
                    return StatusCode(StatusCodes.Status400BadRequest, new ResponseModel { Status = "Error", Message = "an error has occured" });
                return StatusCode(StatusCodes.Status205ResetContent, new ResponseModel { Status = "Success", Message = "password was resetted successfuly" });

            }
            return NotFound("User not found");
        }


        [HttpPost]
        [Route("forgetPassword")]
        public async Task<IActionResult> forgotPassword([FromBody] ResetPasswordModel model)
        {
            var userNameExists = await _userManager.FindByNameAsync(model.UserName);
            if(userNameExists != null)
            {
                var passwordTken = await _userManager.GeneratePasswordResetTokenAsync(userNameExists);


                var link = "http://localhost:4200/ResetPassword?token=" + passwordTken;
                var message = new Message(new string[] { "slim.hammami.atj@gmail.com" }, "Reset password", "Hello dear user, this link is used to generate a new password." + link, null);
                _emailSender.SendEmail(message);

                return Ok();
            }

            return NotFound();
        }

        [HttpPost]
        [Route("changepassword")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            IdentityUser userNameExists = await _userManager.FindByNameAsync(model.UserName);
            
            if (userNameExists != null)
            {
                var result = await _userManager.ChangePasswordAsync(userNameExists, model.Password, model.NewPassword);

                if (!result.Succeeded)
                    return StatusCode(StatusCodes.Status400BadRequest, new ResponseModel { Status = "Error", Message = "an error has occured" });
                return StatusCode(StatusCodes.Status205ResetContent, new ResponseModel { Status = "Success", Message = "password was resetted successfuly" });

            }

            return NotFound("User not found");
        }


        [HttpGet]
        [Route("sendemail")]
        public IEnumerable<WeatherForecast> Send()
        {
            var rng = new Random();
            var message = new Message(new string[] { "slim.hammami.atj@gmail.com" }, "Test email", "This is the content from our email.", null);
            _emailSender.SendEmail(message);
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = "Hello !!!!"
            })
            .ToArray();
        }
        [Route("importfile")]
        [HttpPost]
        public IActionResult Post()
        {
            var rng = new Random();
            var files = Request.Form.Files.Any() ? Request.Form.Files : new FormFileCollection();
            var message = new Message(new string[] { "slim.hammami.atj@gmail.com" }, "Test mail with Attachments", "This is the content from our mail with attachments.", files);
             _emailSender.SendEmail(message);
            return Ok();
        }
    }
}
