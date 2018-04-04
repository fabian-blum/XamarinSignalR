using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using XamarinSignalR.Web.Models;
using XamarinSignalR.Web.Models.AccountViewModels;
using XamarinSignalR.Web.Models.ApiModels;
using XamarinSignalR.Web.Services;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace XamarinSignalR.Web.Controllers
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Produces("application/json")]
    [Route("api/Account")]
    public class ApiAccountController : Controller
    {
        public ApiAccountController(
            IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            IPasswordHasher<ApplicationUser> passwordHasher,
            ILogger<ApiAccountController> logger,
            IEmailSender emailSender)
        {
            Configuration = configuration;
            UserManager = userManager;
            PasswordHasher = passwordHasher;
            Logger = logger;
            EmailSender = emailSender;
        }

        private IConfiguration Configuration { get; }
        private UserManager<ApplicationUser> UserManager { get; }
        private IPasswordHasher<ApplicationUser> PasswordHasher { get; }
        private ILogger<ApiAccountController> Logger { get; }
        private IEmailSender EmailSender { get; }

        // POST api/ApiAccount/token
        [AllowAnonymous]
        [HttpPost("token")]
        public async Task<IActionResult> Token([FromBody] LoginViewModel model)
        {
            try
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null)
                {
                    return Unauthorized();
                }
                if (PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password) == PasswordVerificationResult.Success)
                {
                    var userClaims = await UserManager.GetClaimsAsync(user);

                    var claims = new[]
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Email, user.Email)
                    }.Union(userClaims);

                    var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JwtSecurityToken:Key"]));
                    var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

                    var jwtSecurityToken = new JwtSecurityToken(
                        issuer: Configuration["JwtSecurityToken:Issuer"],
                        audience: Configuration["JwtSecurityToken:Audience"],
                        claims: claims,
                        expires: DateTime.UtcNow.AddDays(13),
                        signingCredentials: signingCredentials
                    );
                    return Ok(new
                    {
                        access_token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                        expiration = jwtSecurityToken.ValidTo
                    });
                }
                return Unauthorized();
            }
            catch (Exception ex)
            {
                Logger.LogError($"error while creating token: {ex}");
                return StatusCode((int)HttpStatusCode.InternalServerError, "error while creating token");
            }
        }

        // POST api/ApiAccount/token
        [AllowAnonymous]
        [HttpPost("tokenWithoutLogin")]
        public IActionResult TokenWithoutLogin([FromBody] string id)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var identity = new ClaimsIdentity(new GenericIdentity(id, "jwt"));

                var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JwtSecurityToken:Key"]));
                var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

                SecurityToken token = tokenHandler.CreateJwtSecurityToken(new SecurityTokenDescriptor
                {
                    Audience = Configuration["JwtSecurityToken:Audience"],
                    Issuer = Configuration["JwtSecurityToken:Issuer"],
                    SigningCredentials = signingCredentials,
                    Expires = DateTime.UtcNow.AddDays(13),
                    Subject = identity
                });

                return Ok(new
                {
                    access_token = tokenHandler.WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            catch (Exception ex)
            {
                Logger.LogError($"error while creating token: {ex}");
                return StatusCode((int)HttpStatusCode.InternalServerError, "error while creating token");
            }
        }

        // GET api/Account/CookieLogin
        [AllowAnonymous]
        [HttpGet("CookieLogin")]
        public async Task<IActionResult> CookieLogin()
        {
            try
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, "jon", ClaimValueTypes.String),
                    new Claim("FullName", "baalalalal")
                };
                var userIdentity = new ClaimsIdentity(claims, "SecureLogin");
                var userPrincipal = new ClaimsPrincipal(userIdentity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    userPrincipal,
                    new AuthenticationProperties
                    {
                        ExpiresUtc = DateTime.UtcNow.AddMinutes(20),
                        IsPersistent = false,
                        AllowRefresh = false
                    });
                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                Logger.LogError($"error while creating token: {ex}");
                return StatusCode((int)HttpStatusCode.InternalServerError, "error while creating token");
            }
        }


        // GET: api/ApiAccount/5
        [HttpGet("GetUser")]
        public async Task<IActionResult> Get()
        {
            var userId = UserManager.GetUserId(User);

            var user = await UserManager.FindByEmailAsync(userId);

            var returnUser = new UserApiModel
            {
                Id = user.Id,
                Email = user.Email,
                UserName = user.UserName,
                Name = user.UserName,
                NormalizedName = user.NormalizedUserName,
                PhoneNumber = user.PhoneNumber
            };

            return Ok(returnUser);
        }

        // POST: api/ApiAccount
        [AllowAnonymous]
        [HttpPost("RegisterUser")]
        public async Task<IActionResult> Post([FromBody]RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    Logger.LogInformation("User created a new account with password.");

                    var code = await UserManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
                    await EmailSender.SendEmailConfirmationAsync(model.Email, callbackUrl);

                    return Ok();
                }
                return BadRequest("Error while creating user");
            }
            return BadRequest("ModelState not valid");
        }

        // PUT: api/ApiAccount/5
        [HttpPut("{id}", Name = "UpdateUser")]
        public async Task<IActionResult> Put(string id, [FromBody]UserApiModel usermodel)
        {
            if (id != usermodel.Id)
            {
                return BadRequest();
            }
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userId = UserManager.GetUserId(User);

            var user = await UserManager.FindByEmailAsync(userId);

            // Mapping Attributes

            user.Id = usermodel.Id;
            user.Email = usermodel.Email;
            user.UserName = usermodel.UserName;
            user.UserName = usermodel.Name;
            user.NormalizedUserName = usermodel.NormalizedName;
            user.PhoneNumber = usermodel.PhoneNumber;

            // Domain Model


            await UserManager.UpdateAsync(user);

            return Ok();
        }

        // DELETE: api/ApiWithActions/5
        [HttpDelete("{id}", Name = "DeleteUser")]
        public async Task<IActionResult> Delete(string id)
        {
            var userId = UserManager.GetUserId(User);

            var user = await UserManager.FindByEmailAsync(userId);

            if (user.Id != id)
            {
                return BadRequest("False user id");
            }

            await UserManager.DeleteAsync(user);
            return Ok();
        }
    }
}
