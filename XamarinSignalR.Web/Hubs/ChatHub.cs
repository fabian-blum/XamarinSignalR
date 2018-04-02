using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace XamarinSignalR.Web.Hubs
{
    [Authorize(AuthenticationSchemes = "Identity.Application" + "," + CookieAuthenticationDefaults.AuthenticationScheme + "," + JwtBearerDefaults.AuthenticationScheme)]
    public class ChatHub : Hub
    {
        private static readonly Dictionary<string, string> ClientsDictionary = new Dictionary<string, string>();

        public Task SendMessage(string user, string message)
        {
            var timestamp = DateTime.Now.ToShortTimeString();

            Debug.WriteLine(Context.ConnectionId);
            Debug.WriteLine(Context.Connection.ConnectionId);
            Debug.WriteLine(Context.Connection.UserIdentifier);

            var x = ClientsDictionary.FirstOrDefault();
            var console = ClientsDictionary.Where(y => y.Value == "console");
            var consoleConnections = console.Select(keyValuePair => keyValuePair.Key).ToList();

            consoleConnections.Add(x.Key);

            return Clients.Clients(consoleConnections).SendAsync("ReceiveMessage", timestamp, user, message); ;
        }

        public void Register(string user)
        {
            ClientsDictionary.Add(Context.ConnectionId, user);
            Debug.WriteLine(Context.ConnectionId + " // " + user);
        }

    }
}
