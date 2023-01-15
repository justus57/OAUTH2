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
        static async Task Main()
        {
            string content_type = "application/x-www-form-urlencoded";
            string scope = "oob";
            string grant_type = "client_credentials";
            string authorization = "Basic 2xpZW50LTAxOnNlY3JldC1rZXktMDI=";

            using (var httpClient = new HttpClient())
            {
                var parameters = new List<KeyValuePair<string, string>>() {
                                  new KeyValuePair<string, string>("scope", "oob"),
                                  new KeyValuePair<string, string>("grant_type", "client_credentials")
                                };

                var requestMessage = new HttpRequestMessage()
                {
                    Method = new HttpMethod("POST"),
                    RequestUri = new Uri("https://api-sandbox.getnet.com.br/auth/oauth/v2/token"),
                    Content = new FormUrlEncodedContent(parameters)
                };

                requestMessage.Content.Headers.ContentType =
                      new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

                requestMessage.Headers.Add("Authorization", authorization);

                var response = await httpClient.SendAsync(requestMessage);
                var responseStatusCode = response.StatusCode;
                var responseBody = await response.Content.ReadAsStringAsync();
            }
            Console.ReadLine();
        }
    }



}
