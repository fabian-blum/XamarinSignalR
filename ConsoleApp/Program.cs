using Microsoft.AspNetCore.SignalR.Client;
using Newtonsoft.Json.Linq;
using RestSharp;
using System;
using System.Net;

namespace ConsoleApp
{
    public class Program
    {
        public static void Main()
        {
            Console.WriteLine("Hello SignalR!");
            Console.ReadKey();

            var token = GetApiKey();

            var con = new HubConnectionBuilder()
                .WithUrl(@"https://localhost:44393/chathub")
                .WithAccessToken(() => token);

            HubConnection x = con.Build();


            x.StartAsync().GetAwaiter().GetResult();

            x.On<string, string, string>("ReceiveMessage", (timestamp, user, message) =>
            {
                Console.WriteLine($@"{timestamp} / {user} / {message}");
            });

            x.SendAsync("Register", "console").GetAwaiter().GetResult();
            x.SendAsync("SendMessage", "Console", "Consoleeeee").GetAwaiter().GetResult();

            Console.ReadKey();
        }

        public static string GetApiKey()
        {
            var restClient = new RestClient(@"https://localhost:44393");

#if DEBUG
            // Accept other SSL Certificates
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
#endif

            var request = new RestRequest("/api/Account/tokenWithoutLogin")
            {
                Method = Method.POST,
                RequestFormat = DataFormat.Json
            };
            request.AddBody("1203809");

            var response = restClient.ExecuteTaskAsync(request).GetAwaiter().GetResult();

            var jobject = JObject.Parse(response.Content);

            var responseData = jobject["access_token"];

            return responseData.ToString();
        }
    }
}
