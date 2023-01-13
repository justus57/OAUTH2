using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace OAUTH2
{
    class Program
    {
      
            // Azure AD registrations:
            // Specifies the Azure AD tenant ID
            static string AadTenantId = "4dfedb10-35ca-4e46-9c2a-0fa40d6968c0";
            // Specifies the Application (client) ID of the console application registration in Azure AD
          static string ClientId = "768aaa2d-b574-4d8f-8efa-0f71c3bc18c4";
            // Specifies the redirect URL for the client that was configured for console application registration in Azure AD
            static string ClientRedirectUrl = "https://businesscentral.dynamics.com/";
            // Specifies the APP ID URI that is configured for the registered Business Central application in Azure AD
            static string ServerAppIdUri = "https://login.windows.net/4dfedb10-35ca-4e46-9c2a-0fa40d6968c0/oauth2/authorize?resource=https://api.businesscentral.dynamics.com";

            static void Main()
            {
                // Get access token from Azure AD. This will show the login dialog.
                // Get access token from Azure AD. This will show the login dialog.
                var client = PublicClientApplicationBuilder.Create(ClientId)
                
                    .WithAuthority("https://login.microsoftonline.com/" + AadTenantId, false)
                    .WithRedirectUri(ClientRedirectUrl)
                    .Build();
                AuthenticationResult authenticationResult = client.AcquireTokenInteractive(new string[] { $"{ServerAppIdUri}/.default" }).ExecuteAsync().GetAwaiter().GetResult();
                // Connect to the Business Central OData web service and display a list of customers
                //var nav = new NAV.NAV(new Uri(< "https://localhost:7048/BC/ODataV4/Company('CRONUS%20International%20Ltd.'>)"));
                //nav.BuildingRequest += (sender, eventArgs) => eventArgs.Headers.Add("Authorization", authenticationResult.CreateAuthorizationHeader());

                //// Retrieve and return a list of the customers 
                //foreach (var customer in nav.Customer)
                //{
                //    Console.WriteLine("Found customer: " + customer.Name);
                //}
                Console.ReadLine();
            }
        }
                                              
   
   
}
