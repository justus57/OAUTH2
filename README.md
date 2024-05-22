# README

## Overview
This application demonstrates how to implement OAuth 2.0 authorization to obtain an access token from a Microsoft Azure AD tenant. The code includes methods to generate the necessary data, send requests to the authorization and token endpoints, and handle responses.

## Prerequisites
- .NET Framework or .NET Core installed on your machine
- A registered application in Azure AD with client ID, client secret, and redirect URI
- Visual Studio or any C# IDE

## Configuration
Replace the placeholder values in the code with your application's credentials and endpoints:
- `clientID`: Your application's client ID
- `clientSecret`: Your application's client secret
- `redirectURI`: The redirect URI registered in Azure AD
- `codeVerifier`: The authorization endpoint URL
- `scope`: The scope of access required (e.g., `https://mail.google.com/`)

## Code Explanation

### Main Method
The `Main` method is the entry point of the application. It performs the following steps:
1. Extracts the authorization code and stores client credentials.
2. Generates the data required for the token request using `GenerateRequestPostData`.
3. Calls `GetAccessToken` to exchange the authorization code for an access token.

### GenerateRequestPostData Method
This method creates the POST data required to request the token. It formats the client assertion, grant type, and redirect URI as URL-encoded parameters.

```csharp
public static string GenerateRequestPostData(string appSecret, string authCode, string callbackUrl)
{
    return String.Format("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={1}&redirect_uri={2}",
        HttpUtility.UrlEncode(appSecret),
        HttpUtility.UrlEncode(authCode),
        callbackUrl
    );
}
```

### GetAuthorizationCode Method
This method generates an authorization request, opens it in the browser, and listens for the OAuth response.

```csharp
static string GetAuthorizationCode(string clientID, string codeVerifier, string redirectURI)
{
    // Code to generate state, code challenge, and build the authorization request URI
    // Opens the authorization request in the default browser and waits for the response
}
```

### GetAccessToken Method
This method exchanges the authorization code for an access token by sending a POST request to the token endpoint. It handles the response and returns the access token.

```csharp
static string GetAccessToken(string code, string clientID, string clientSecret, string codeVerifier, string redirectURI)
{
    // Code to build the token request body and send the request
    // Handles the response and returns the access token
}
```

### Utility Methods
- `GetRandomUnusedPort`: Generates a random unused port for the redirect URI.
- `RandomDataBase64Url`: Generates random data in Base64 URL-encoded format.
- `Sha256`: Computes SHA256 hash of the input string.
- `Base64UrlEncodeNoPadding`: Encodes bytes to a Base64 URL string without padding.

## How to Run
1. Open the project in Visual Studio or your preferred C# IDE.
2. Replace the placeholder values with your actual client ID, client secret, and redirect URI.
3. Build and run the project.
4. The application will open the authorization request in the default browser.
5. After authorizing, the application will exchange the authorization code for an access token and print it to the console.

## Important Notes
- Ensure that your redirect URI in the Azure AD application matches the one used in the code.
- Handle exceptions and errors gracefully in a production environment.
- Secure your client credentials and do not expose them in the source code.

## License
This code is provided "as is", without warranty of any kind. Use it at your own risk.

