using Microsoft.AspNetCore.SignalR.Client;
using System;

namespace ConsoleApp
{
    public class Program
    {
        public static void Main()
        {
            Console.WriteLine("Hello SignalR!");
            Console.ReadKey();


            var con = new HubConnectionBuilder()
                .WithUrl(@"https://localhost:44393/chathub");

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
    }
}
