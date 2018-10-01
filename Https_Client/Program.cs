using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Https_Client
{
    class Program
    {
        static void Main(string[] args)
        {
            string url = "https://www.google.com";
            Uri uri = new Uri(url);

            TcpClient client = new TcpClient(uri.Host, 443);
            Console.WriteLine("Client connected.");
            // Create an SSL stream that will close the client's stream.
            SslStream sslStream = new SslStream(  client.GetStream(), false,  new RemoteCertificateValidationCallback(ValidateServerCertificate),  null );
            try
            {
                sslStream.AuthenticateAsClient(uri.Host);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
            }

            StringBuilder strb = new StringBuilder();
            strb.AppendLine("GET / HTTP1.1");
            strb.AppendLine();
            byte[] send_buf = Encoding.UTF8.GetBytes(strb.ToString());
            sslStream.Write(send_buf, 0, send_buf.Length);

            byte[] read_buf = new byte[8192];
            MemoryStream mm = new MemoryStream();
            while (true)
            {
                int read_len = sslStream.Read(read_buf, 0, read_buf.Length);
                if(read_len == 0)
                {
                    break;
                }
                else
                {
                    mm.Write(read_buf, 0, read_len);
                }
            }
            
            Console.WriteLine(Encoding.UTF8.GetString(mm.ToArray()));
            
        }

        public static bool ValidateServerCertificate( object sender,  X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }

    }
}
