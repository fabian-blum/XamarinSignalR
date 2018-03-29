using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;

namespace XamarinSignalR.Web.Hubs
{
    public class ChatHub : Hub
    {
        public Task Send(string data)
        {
            return Clients.All.SendAsync("Send", data);
        }
    }
}
