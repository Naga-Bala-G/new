# Introduction 
TODO: Give a short introduction of your project. Let this section explain the objectives or the motivation behind this project. 

# Getting Started
TODO: Guide users through getting your code up and running on their own system. In this section you can talk about:
1.	Installation process
2.	Software dependencies
3.	Latest releases
4.	API references

# Build and Test
TODO: Describe and show how to build your code and run the tests. 

# Contribute
TODO: Explain how other users and developers can contribute to make your code better. 

If you want to learn more about creating good readme files then refer the following [guidelines](https://docs.microsoft.com/en-us/azure/devops/repos/git/create-a-readme?view=azure-devops). You can also seek inspiration from the below readme files:
- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)



Authentication & Authorization of SSO

JAVA setup in system
To set up the Java environment variables on your system, you’ll need to configure the JAVA_HOME variable and update your system's PATH to include the Java binaries. Here's how you can do this on different operating systems:
For Windows:
1.	Install Java:
o	Download and install the Java Development Kit (JDK) from the official Oracle website or OpenJDK.
2.	Find the Java Installation Path:
o	The JDK is usually installed in a directory like C:\Program Files\Java\jdk-XX, where XX represents the version number.
3.	Set JAVA_HOME and Update PATH:
o	Open the Start Menu and search for "Environment Variables" or "Edit the system environment variables" and select it.
o	In the System Properties window, click on the "Environment Variables" button.
o	Under "System variables", click "New" to create a new environment variable.
	Variable name: JAVA_HOME
	Variable value: The path to your JDK installation, e.g., C:\Program Files\Java\jdk-XX
o	Find the Path variable in the "System variables" section and select it, then click "Edit".
o	Click "New" and add %JAVA_HOME%\bin to the list. This ensures that the Java executables are available in your command line.
o	Click "OK" to close all dialogs.
4.	Verify Installation:
o	Open Command Prompt (cmd) and type java -version and javac -version to ensure Java is correctly installed and the PATH is set up properly.


Keyclok setup in system
Keycloak is an open-source identity and access management tool that provides single sign-on (SSO) and identity management capabilities. To get Keycloak up and running, you'll need to follow several steps for installation, configuration, and administration. Here’s a detailed guide:
1.	Download Keycloak:
o	Visit the Keycloak download page and download the latest version.
either the zip file or Tar.GZ file
2.	Extract and Start Keycloak:
o	Extract the .zip file or Tar.GZ to a directory of your choice.
o	Open a Command Prompt (cmd) or PowerShell, navigate to the Keycloak directory, and run:
cmd
cd path\to\keycloak-21.0.0
.\bin\kc.bat start
o	Keycloak will be accessible at http://localhost:8080.
2. Initial Setup
Access Keycloak Admin Console:
o	Open a web browser and go to http://localhost:8080/auth/admin/.
o	You'll need to create an initial admin user.

3. Create a Realm
1.	Log in: Go to the Keycloak admin console at http://localhost:8080/auth/admin and log in with the admin credentials.
2.	Create Realm:
o	In the left-hand menu, click on Master (or the current realm name).
o	Click Add realm and enter a name for your realm(e.g., myrealm), then click Create.
4. Create a Client
1.	Navigate to Clients:
o	Select your realm from the drop-down menu.
o	Go to Clients in the left-hand menu and click Create.
2.	Configure Client:
o	Client ID: Enter a unique ID for your client (e.g., myclient).
o	Client Protocol: Select openid-connect or saml depending on your preference.
o	Root URL: Enter the root URL of the application you want to integrate.(e.g., http://localhost:5000)
o	Click Save.
3.	Configure Client Settings:
o	Access Type: Set to confidential or public based on your application’s needs.(client authentication : enabled)
o	Redirect URIs: Add the URIs where Keycloak will redirect after authentication.
o	Web Origins: Specify the allowed origins for your application.
o	Configure other settings as needed (e.g., client secrets if using confidential clients).
Create Users
1.	Navigate to Users:
o	Go to Users in the left-hand menu and click Add user.
2.	Enter User Information:
o	Provide details like username, email, and enable the user.
o	Click Save.
3.	Set User Credentials:
o	After saving, go to the Credentials tab and set a password for the user.
Add 3-4 users with different users for rbac 
(user1@gmail.com – first name: user1 lastname: user1,
 user2@gmail.com– first name: user2 lastname: user2,
 user3@gmail.com– first name: user3 lastname: user3,
 user4@gmail.com– first name: user4 lastname: user4. )

3. Integrate Applications
For OAuth 2.0 / OpenID Connect
1.	Obtain Credentials:
o	Navigate to Clients and select your client.
o	Go to the Credentials tab to find the client ID and client secret.
2.	Configure Application:
o	Use the client ID and client secret to configure your application to authenticate using Keycloak. Most modern frameworks and libraries support integration with OAuth 2.0 / OpenID Connect.
Test Your Setup
1.	Access Your Application:
o	Navigate to your application’s login page through “localhost:8080/realms/myrealm/account”
o	You should be redirected to Keycloak for authentication.
2.	Log In:
o	Use the credentials you created to log in.
o	Verify that you are redirected back to your application after successful authentication.

Keycloak checking setup for postman

Using Postman to interact with Keycloak involves sending HTTP requests to the Keycloak server for various operations like login, introspection, and token refresh. Here’s how you can test these operations with Postman.
1. Login (Obtain Access Token)
To authenticate a user and obtain an access token from Keycloak, you’ll need to make a POST request to the token endpoint.
Endpoint:
Method :POST  
Endpoint: http://<keycloak-server>/auth/realms/<realm-name>/protocol/openid-connect/token
Headers:
•	Content-Type: application/x-www-form-urlencoded
Body (x-www-form-urlencoded):
•	grant_type: password
•	client_id: Your client ID
•	client_secret: Your client secret (only for confidential clients)
•	username: The username of the user
•	password: The password of the user
Response:
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
2. Introspect Token
To introspect an access token and get information about it, use the token introspection endpoint. This endpoint requires an access token to be sent as part of the request.
Endpoint:
Method : POST
Endpoint : http://<keycloak-server>/auth/realms/<realm-name>/protocol/openid-connect/token/introspect
Headers:
•	Content-Type: application/x-www-form-urlencoded
•	Authorization: Basic <Base64 encoded client_id:client_secret>
Body (x-www-form-urlencoded):
•	token: The access token you want to introspect
Response:
{
    "active": true,
    "exp": 1694925405,
    "iat": 1694919805,
    "aud": "my-client",
    "sub": "user-id",
    "session_state": "session-id",
    "realm_access": {
        "roles": ["user"]
    },
    "resource_access": {
        "my-client": {
            "roles": ["role"]
        }
    }
}
3. Refresh Token
To refresh an access token when it expires, you use the refresh token endpoint. This involves making a POST request to the token endpoint but with the grant_type set to refresh_token.
Endpoint:
Method : POST
Endpoint : http://<keycloak-server>/auth/realms/<realm-name>/protocol/openid-connect/token
Headers:
•	Content-Type: application/x-www-form-urlencoded
Body (x-www-form-urlencoded):
•	grant_type: refresh_token
•	client_id: Your client ID
•	client_secret: Your client secret (only for confidential clients)
•	refresh_token: The refresh token obtained previously
Response:
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

API Setup with postman
Authentication Endpoints
1. Login
•	Endpoint: /api/auth/login
•	Method: POST
•	Description: Authenticates a user and returns an access token along with user roles.
Request Body:
json

{
    "username": "user@example.com",
    "password": "your_password"
}
Responses:
•	200 OK
json

{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "roles": ["role1", "role2"]
}
•	400 Bad Request
json

{
    "error": "Missing parameters"
}
•	401 Unauthorized
json

{
    "error": "Authentication failed"
}
•	500 Internal Server Error
json

{
    "error": "Error during login process: <error_message>"
}
2. User Details
•	Endpoint: /api/auth/user-details
•	Method: POST
•	Description: Fetches details of the user based on the provided access token.
Headers:
•	Authorization: Bearer <access_token>
Responses:
•	200 OK
json

{
    "active": true,
    "exp": 1234567890,
    "iat": 1234567890,
    "realm_access": {
        "roles": ["role1", "role2"]
    }
    // other user details
}
•	400 Bad Request
json

{
    "error": "Authorization header is missing"
}
•	401 Unauthorized
json

{
    "error": "Token is not active or invalid"
}
•	500 Internal Server Error
json

{
    "error": "Error fetching user details: <error_message>"
}
3. Refresh Token
•	Endpoint: /api/auth/refresh
•	Method: POST
•	Description: Refreshes the access token using the provided refresh token.
Request Body:
json

{
    "refresh_token": "your_refresh_token"
}
Responses:
•	200 OK
json

{
    "access_token": "new_access_token",
    "refresh_token": "new_refresh_token"
}
•	400 Bad Request
json

{
    "error": "Missing refresh token"
}
•	401 Unauthorized
json

{
    "error": "Token refresh failed"
}
•	500 Internal Server Error
json

{
    "error": "Error refreshing token: <error_message>"
}
User Management Endpoints
4. Get Users
•	Endpoint: /api/users
•	Method: GET
•	Description: Fetches the list of users from Keycloak and their roles.
Headers:
•	Authorization: Bearer <admin_access_token>
Responses:
•	200 OK
json

[
    {
        "first_name": "John",
        "last_name": "Doe",
        "name": "johndoe",
        "email": "john.doe@example.com",
        "roles": {
            "realm_roles": ["role1", "role2"],
            "client_roles": {
                "client1": ["client_role1"],
                "client2": []
            }
        }
    }
    // more users
]
•	500 Internal Server Error
json

{
    "error": "Error fetching users: <error_message>"
}
5. Fetch User Details by Email
•	Endpoint: /api/users/details
•	Method: GET
•	Description: Fetches details for a specific user by their email address.
Query Parameters:
•	email (string, required): The email address of the user.
Request Example:
sql

GET /api/users/details?email=user@example.com
Responses:
•	200 OK
json
Copy code
{
    "first_name": "John",
    "last_name": "Doe",
    "email": "user@example.com",
    "roles": {
        "realm_roles": ["user"],
        "client_roles": {
            "client1": ["role1"],
            "client2": ["role2"]
        }
    }
}
•	400 Bad Request
json

{
    "error": "Email parameter is required"
}
•	404 Not Found
json

{
    "error": "User not found"
}
•	500 Internal Server Error
json

{
    "error": "Error fetching user details"
}
6. Fetch All Users and Their Roles
•	Endpoint: /api/roles
•	Method: GET
•	Description: Fetches a list of all users along with their given names and roles.
Request Example:
bash

GET /api/roles
Responses:
•	200 OK
json

[
    {
        "given_name": "John",
        "role": ["user"]
    },
    {
        "given_name": "Jane",
        "role": ["admin"]
    }
    // more users
]
•	500 Internal Server Error
json

{
    "error": "Error fetching user roles"
}
7. Change User Role
•	Endpoint: /api/roles/change_role
•	Method: POST
•	Description: Changes a user's role by removing the current role and assigning a new one, provided the requester is an admin.
Request Body:
json

{
    "username": "user@example.com",
    "old_role": "user",
    "new_role": "admin"
}
Responses:
•	200 OK
json

{
    "message": "Role changed from user to admin for user user@example.com"
}
•	400 Bad Request
json

{
    "error": "Missing parameters"
}
•	403 Forbidden
json

{
    "error": "Forbidden"
}
•	500 Internal Server Error
json

{
    "error": "Error changing role"
}
8. Remove User Role
•	Endpoint: /api/roles/remove
•	Method: POST
•	Description: Removes a role from a user, provided the requester is an admin.
Request Body:
json

{
    "username": "user@example.com",
    "role": "user"
}
Responses:
•	200 OK
json

{
    "message": "Role user removed from user user@example.com"
}
•	400 Bad Request
json

{
    "error": "Missing parameters"
}
•	403 Forbidden
json

{
    "error": "Forbidden"
}
•	500 Internal Server Error
json

{
    "error": "Error removing role"
}
9. Assign User Role
•	Endpoint: /api/roles/assign
•	Method: POST
•	Description: Assigns a role to a user, provided the requester is an admin.
Request Body:
json

{
    "username": "user@example.com",
    "role": "admin"
}
Responses:
•	200 OK
json

{
    "message": "Role admin assigned to user user@example.com"
}
•	400 Bad Request
json

{
    "error": "Missing parameters"
}
•	403 Forbidden
json

{
    "error": "Forbidden"
}
•	500 Internal Server Error
json

{
    "error": "Error assigning role"
}
Common Error Responses
•	400 Bad Request: Malformed request due to missing parameters.
json

{
    "error": "Error message"
}
•	401 Unauthorized: Authentication failed or token is invalid.
json

{
    "error": "Token is not active or invalid"
}
•	403 Forbidden: User lacks necessary permissions.
json

{
    "error": "Forbidden"
}
•	404 Not Found: Requested resource not found.
json

{
    "error": "Error message"
}
•	500 Internal Server Error: Unexpected error occurred on the server.
json

{
    "error": "Error message"
}

