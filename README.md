Sample Controller to show coding styles

This controller supports registration, login, JWT authentication, sign up and sign in using Email, Google and Facebook. This also allows the client to change password and perform refresh token.

The controller is using .NetCore Identity to manage the users registration, login and password change.

TokenService is injected to use for generating access and refresh tokens.

I also used AutoMapper for easier DTO mapping from database entities to avoid sharing unnecessary details to client.
