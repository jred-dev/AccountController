using System.Security.Claims;
using API.Data.Entities;
using API.Enums;
using API.Models.Dtos;
using API.Services.Interfaces;
using AutoMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [ApiController]
    [Route("api/[Controller]")]
    public class AccountController : ControllerBase
    {
        const string REQ_ERR = "An error was encountered during the request";
        private readonly UserManager<AppUser> _userManager;
        private readonly IMapper _mapper;
        private readonly ITokenService _token;

        private readonly ILogger<AccountController> _logger;

        public AccountController(
           UserManager<AppUser> usermanager,
           IMapper mapper,
           ITokenService token,
           ILogger<AccountController> logger)
        {
            _userManager = usermanager;
            _mapper = mapper;
            _token = token;
            _logger = logger;
        }

        /// <summary>
        /// Register endpoint
        /// </summary>
        /// <param name="register"></param>
        /// <returns></returns>
        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto register)
        {
            try
            {
                if (await _userManager.Users.AnyAsync(_ => _.Email.ToLower() == register.Email.ToLower()))
                    return BadRequest("Email address already exists");

                var user = _mapper.Map<AppUser>(register);
                user.AuthenticationType = AuthenticationType.Email.ToString();
                var result = await CreateUser(user, register.Password);

                if (!result.Succeeded) return BadRequest(result.Errors.ToList().FirstOrDefault().Description);

                return Ok();
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user registration");
                return BadRequest(REQ_ERR);
            }
        }

        /// <summary>
        /// Login endpoint
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginDto login)
        {
            try
            {
                var user = await _userManager.Users.SingleOrDefaultAsync(_ => _.UserName.ToLower() == login.UserName.ToLower());
                if (user == null) return BadRequest("Invalid email address");

                var result = await _userManager.CheckPasswordAsync(user, login.Password);
                if (!result)
                    return BadRequest("Invalid email or password");

                var userAccess = await CreateUserAccess(user);

                return Ok(userAccess);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user login");
                return BadRequest(REQ_ERR);
            }
        }

        /// <summary>
        /// Change pass
        /// </summary>
        /// <param name="changePasswordDto"></param>
        /// <returns></returns>
        [HttpPost("changePassword")]
        public async Task<ActionResult> ChangePassword(ChangePasswordDto changePasswordDto)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(User.Identity.Name);
                if (user == null) return NotFound("User not found");

                var result = await _userManager.ChangePasswordAsync(user, changePasswordDto.OldPassword, changePasswordDto.NewPassword);
                if (!result.Succeeded)
                    return BadRequest(result.Errors.FirstOrDefault()?.Description);

                return Ok("Password changed successfully");
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user change password");
                return BadRequest(REQ_ERR);
            }
        }

        /// <summary>
        /// Sign in using google auth
        /// </summary>
        /// <returns></returns>
        [HttpGet("signin-google")]
        public IActionResult SignInWithGoogle()
        {
            try
            {
                var properties = new AuthenticationProperties { RedirectUri = Url.Action("authorize") };
                return Challenge(properties, GoogleDefaults.AuthenticationScheme);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user google signin");
                return BadRequest(REQ_ERR);
            }
        }

        /// <summary>
        /// Sign in using facebook auth
        /// </summary>
        /// <returns></returns>
        [HttpGet("signin-facebook")]
        public IActionResult SignInWithFacebook()
        {
            try
            {
                var properties = new AuthenticationProperties { RedirectUri = Url.Action("authorize") };
                return Challenge(properties, FacebookDefaults.AuthenticationScheme);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user facebook signin");
                return BadRequest(REQ_ERR);
            }
        }

        /// <summary>
        /// Authorize endpoint
        /// </summary>
        /// <returns></returns>
        [HttpGet("authorize")]
        public async Task<IActionResult> Authorize()
        {
            try
            {
                var authResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                if (authResult?.Succeeded != true)
                    return BadRequest("External login failed");

                var user = await _userManager.FindByNameAsync(authResult.Principal.FindFirstValue(ClaimTypes.Email));
                bool existingUser = true;
                //if new user create account
                //gets info from claims
                if (user == null)
                {
                    existingUser = false;
                    user = new AppUser
                    {
                        NameIdentifier = authResult.Principal.FindFirstValue(ClaimTypes.NameIdentifier),
                        UserName = authResult.Principal.FindFirstValue(ClaimTypes.Email),
                        Email = authResult.Principal.FindFirstValue(ClaimTypes.Email),
                        FirstName = authResult.Principal.FindFirstValue(ClaimTypes.Name).Split(' ')[0],
                        LastName = authResult.Principal.FindFirstValue(ClaimTypes.Name).Split(' ')[1],
                        AuthenticationType = authResult.Principal.Identity.AuthenticationType
                    };

                    var result = await CreateUser(user);
                    if (!result.Succeeded) return BadRequest(result.Errors.ToList().FirstOrDefault().Description);
                }

                var userAccess = await CreateUserAccess(user);
                userAccess.EU = existingUser;
                return Ok(userAccess);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user authorization process");
                return BadRequest(REQ_ERR);
            }
        }

        #region PRIVATE METHODS
        private async Task<IdentityResult> CreateUser(AppUser appUser, string password = "")
        {
            var result = password != string.Empty ? await _userManager.CreateAsync(appUser, password) : await _userManager.CreateAsync(appUser);
            if (!result.Succeeded) return result;

            var roleResult = await _userManager.AddToRoleAsync(appUser, Constants.AccountType.User);
            return roleResult;
        }

        private async Task<UserDto> CreateUserAccess(AppUser appUser)
        {
            var accessToken = await _token.GenerateAccessToken(appUser);
            var refreshToken = await _token.GenerateRefreshToken();

            var userToken = new UserDto()
            {
                Id = appUser.NameIdentifier ?? appUser.Id.ToString(),
                Name = $"{appUser.FirstName} {appUser.LastName}",
                Email = appUser.Email,
                Username = appUser.UserName,
                Token = accessToken,
                RefreshToken = refreshToken
            };

            return userToken;
        }
    }
    #endregion
}
