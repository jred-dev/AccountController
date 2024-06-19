Sample Controller to show coding styles

This controller supports registration, login, JWT authentication, sign up and sign in using Email, Google and Facebook. This also allows the client to change password and perform refresh token.

The controller is using .NetCore Identity to manage the users registration, login and password change.

TokenService is injected to use for generating access and refresh tokens.

I also used AutoMapper for easier DTO mapping from database entities to avoid sharing unnecessary details to client.



- Register Endpoint:
    - Purpose: This endpoint registers a new user.
    - Description:
        - The Register method accepts a RegisterDto object containing registration data (such as email, password, etc.).
        - It checks if the provided email address already exists in the system.
        - If not, it maps the registration data to an AppUser object and creates the user.
        - If successful, it returns an HTTP 200 (OK) response.
        - If any errors occur during registration, it returns an appropriate error response.

- Login Endpoint:
    - Purpose: This endpoint authenticates a user by validating their credentials.
    - Description:
        - The Login method accepts a LoginDto object containing login data (username and password).
        - It finds the user based on the provided username (email address).
        - If the user exists, it checks if the provided password matches the stored password.
        - If successful, it generates user access (tokens, session, etc.) and returns an HTTP 200 (OK) response.
        - Otherwise, it returns an appropriate error response.

- ChangePassword Endpoint:
    - Purpose: This endpoint allows users to change their password.
    - Description:
        - The ChangePassword method accepts a ChangePasswordDto object containing old and new passwords.
        - It finds the user based on the current user's identity.
        - If the user exists, it attempts to change the password.
        - If successful, it returns an HTTP 200 (OK) response.
        - Otherwise, it returns an appropriate error response.

- SignInWithGoogle Endpoint:
    - Purpose: Initiates Google authentication for the user.
    - Description:
        - The SignInWithGoogle method sets the redirect URI for Google authentication.
        - It challenges the user using Google authentication, which redirects them to the Google login page.
        - Upon successful authentication, Google sends the user back to the specified redirect URI.

- SignInWithFacebook Endpoint:
    - Purpose: Initiates Facebook authentication for the user.
    - Description:
        - The SignInWithFacebook method sets the redirect URI for Facebook authentication.
        - It challenges the user using Facebook authentication, redirecting them to the Facebook login page.
        - After successful authentication, Facebook sends the user back to the specified redirect URI.

- Authorize Endpoint:
    - Purpose: Handles user authorization based on external authentication providers.
    - Description:
        - The Authorize method is typically called after successful external authentication (Google, Facebook, etc.).
        - It extracts user information from claims (e.g., email, name).
        - If the user already exists, it generates user access tokens (access and refresh tokens).
        - If the user is new, it creates an account and then generates tokens.
        - Returns an HTTP 200 (OK) response with user access information.

- CreateUser Method:
    - Purpose: Creates a new user account.
    - Description:
        - The CreateUser method creates an AppUser (user entity) based on the provided data.
        - It optionally accepts a password for the user.
        - If successful, it assigns the 'User' role to the user.
        - Returns an IdentityResult indicating success or failure.

