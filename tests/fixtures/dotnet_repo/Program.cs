using System;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Dapper;
using HyperSql.Client;

namespace FixtureApp
{
    class Program
    {
        static void Main()
        {
            var data = FetchAsync().Result;
            try
            {
                Console.WriteLine(data);
            }
            catch (Exception)
            {
            }
        }

        static async Task<string> FetchAsync()
        {
            await Task.Delay(1);
            return "ok";
        }

        static async void FireAndForget()
        {
            await Task.Delay(1);
        }

        static string BuildQuery(string userId)
        {
            return $"SELECT * FROM Users WHERE Id = {userId}";
        }
    }
}
