using Microsoft.AspNetCore.SignalR;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace XamarinSignalR.Web.Hubs
{
    public class ChatHub : Hub
    {
        public Task SendMessage(string user, string message)
        {
            string timestamp = DateTime.Now.ToShortTimeString();

            Debug.WriteLine(Context.ConnectionId);
            Debug.WriteLine(Context.Connection.ConnectionId);
            Debug.WriteLine(Context.Connection.UserIdentifier);




            return Clients.User("9bed5602-d7c4-4ec6-a0f0-165e6834d3da").SendAsync("ReceiveMessage", timestamp, user, message);
        }
    }
}
