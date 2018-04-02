using Microsoft.AspNetCore.SignalR;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace XamarinSignalR.Web.Hubs
{

    public class ChatHub : Hub
    {

        private static Dictionary<string, string> _clients = new Dictionary<string, string>();
        private static int i;

        public Task SendMessage(string user, string message)
        {
            string timestamp = DateTime.Now.ToShortTimeString();

            Debug.WriteLine(Context.ConnectionId);
            Debug.WriteLine(Context.Connection.ConnectionId);
            Debug.WriteLine(Context.Connection.UserIdentifier);

            var x = _clients.FirstOrDefault();
            var console = _clients.Where(y => y.Value == "console");
            List<string> consoleConnections = new List<string>();
            foreach (var keyValuePair in console)
            {
                consoleConnections.Add(keyValuePair.Key);
            }

            consoleConnections.Add(x.Key);

            return Clients.Clients(consoleConnections).SendAsync("ReceiveMessage", timestamp, user, message); ;
        }

        public void Register(string user)
        {
            _clients.Add(Context.ConnectionId, user);
            Debug.WriteLine(Context.ConnectionId + " // " + user);
        }

    }
}
