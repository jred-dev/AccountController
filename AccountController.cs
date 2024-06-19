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
        /// Registers a new user.
        /// </summary>
        /// <param name="register">The registration data.</param>
        /// <returns>An HTTP response indicating success or failure.</returns>
        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto register)
        {
            try
            {
                // Check if the email address already exists
                if (await _userManager.Users.AnyAsync(_ => _.Email.ToLower() == register.Email.ToLower()))
                    return BadRequest("Email address already exists");

                // Map the registration data to an AppUser object
                var user = _mapper.Map<AppUser>(register);
                user.AuthenticationType = AuthenticationType.Email.ToString();

                // Create the user
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
        /// Authenticates a user by validating their credentials.
        /// </summary>
        /// <param name="login">The login data.</param>
        /// <returns>An HTTP response indicating success or failure.</returns>
        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginDto login)
        {
            try
            {
                // Find the user based on the provided username
                var user = await _userManager.Users.SingleOrDefaultAsync(_ => _.UserName.ToLower() == login.UserName.ToLower());
                if (user == null)
                    return BadRequest("Invalid email address");

                // Check if the provided password matches the user's stored password
                var result = await _userManager.CheckPasswordAsync(user, login.Password);
                if (!result)
                    return BadRequest("Invalid email or password");

                // Create user access (e.g., generate tokens, set session, etc.)
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
        /// Changes the user's password.
        /// </summary>
        /// <param name="changePasswordDto">The data for changing the password.</param>
        /// <returns>An HTTP response indicating success or failure.</returns>
        [HttpPost("changePassword")]
        public async Task<ActionResult> ChangePassword(ChangePasswordDto changePasswordDto)
        {
            try
            {
                // Find the user based on the current user's identity
                var user = await _userManager.FindByNameAsync(User.Identity.Name);
                if (user == null)
                    return NotFound("User not found");

                // Attempt to change the password
                var result = await _userManager.ChangePasswordAsync(user, changePasswordDto.OldPassword, changePasswordDto.NewPassword);
                if (!result.Succeeded)
                    return BadRequest(result.Errors.FirstOrDefault()?.Description);

                return Ok("Password changed successfully");
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user password change");
                return BadRequest(REQ_ERR);
            }
        }


        /// <summary>
        /// Initiates Google authentication for the user.
        /// </summary>
        /// <returns>An HTTP response that redirects to the Google authentication provider.</returns>
        [HttpGet("signin-google")]
        public IActionResult SignInWithGoogle()
        {
            try
            {
                // Set the redirect URI for Google authentication
                var properties = new AuthenticationProperties { RedirectUri = Url.Action("authorize") };

                // Challenge the user using Google authentication
                return Challenge(properties, GoogleDefaults.AuthenticationScheme);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user Google sign-in");
                return BadRequest(REQ_ERR);
            }
        }


        /// <summary>
        /// Initiates Facebook authentication for the user.
        /// </summary>
        /// <returns>An HTTP response that redirects to the Facebook authentication provider.</returns>
        [HttpGet("signin-facebook")]
        public IActionResult SignInWithFacebook()
        {
            try
            {
                // Set the redirect URI for Facebook authentication
                var properties = new AuthenticationProperties { RedirectUri = Url.Action("authorize") };

                // Challenge the user using Facebook authentication
                return Challenge(properties, FacebookDefaults.AuthenticationScheme);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error was encountered during user Facebook sign-in");
                return BadRequest(REQ_ERR);
            }
        }


        /// <summary>
        /// Handles user authorization based on external authentication providers.
        /// </summary>
        /// <returns>An HTTP response indicating success or failure.</returns>
        [HttpGet("authorize")]
        public async Task<IActionResult> Authorize()
        {
            try
            {
                // Authenticate the user using the specified authentication scheme
                var authResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                if (authResult?.Succeeded != true)
                    return BadRequest("External login failed");

                // Find the user based on the email obtained from claims
                var user = await _userManager.FindByNameAsync(authResult.Principal.FindFirstValue(ClaimTypes.Email));
                bool existingUser = true;

                // If the user is new, create an account and extract relevant information from claims
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
                    if (!result.Succeeded)
                        return BadRequest(result.Errors.ToList().FirstOrDefault().Description);
                }

                // Create user access (e.g., generate tokens, set session, etc.)
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
        /// <summary>
        /// Creates a new user account.
        /// </summary>
        /// <param name="appUser">The user to create.</param>
        /// <param name="password">Optional password for the user.</param>
        /// <returns>An IdentityResult indicating success or failure.</returns>
        private async Task<IdentityResult> CreateUser(AppUser appUser, string password = "")
        {
            // Create the user with the specified password (if provided)
            var result = password != string.Empty
                ? await _userManager.CreateAsync(appUser, password)
                : await _userManager.CreateAsync(appUser);

            if (!result.Succeeded)
                return result;

            // Assign the 'User' role to the newly created user
            var roleResult = await _userManager.AddToRoleAsync(appUser, Constants.AccountType.User);
            return roleResult;
        }


        /// <summary>
        /// Creates user access tokens for the given <paramref name="appUser"/>.
        /// </summary>
        /// <param name="appUser">The user for whom to generate tokens.</param>
        /// <returns>A <see cref="UserDto"/> containing access and refresh tokens.</returns>
        private async Task<UserDto> CreateUserAccess(AppUser appUser)
        {
            // Generate an access token for the user
            var accessToken = await _token.GenerateAccessToken(appUser);

            // Generate a refresh token
            var refreshToken = await _token.GenerateRefreshToken();

            // Create a UserDto with relevant information
            var userToken = new UserDto
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
