using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Management;
using System.Net.Http;
using System.Text.Json;
using AuthApi;

namespace authtest
{
    public partial class Form1 : Form
    {
        public static int box = 27837;

        public Form1()
        {
            InitializeComponent();
            textBox3.Text = getMotherBoardID();
        }

        public String getMotherBoardID()
        {
            String serial = "";
            try
            {
                ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard");
                ManagementObjectCollection moc = mos.Get();

                foreach (ManagementObject mo in moc)
                {
                    serial = mo["SerialNumber"].ToString();
                }
                return serial;
            }
            catch (Exception)
            {
                return serial;
            }
        }

        private async void fuckbillion(object sender, EventArgs e)
        {
            // Preparar os parâmetros para a função SendAsync
            string method = "login";
            string username = textBox1.Text;
            string password = textBox2.Text;
            string hwid = textBox3.Text;

            // Chamando o método de autenticação
            var cenk = await Authenticator.SendAsync(method, username, password, hwid);

            var message = cenk.Message;
            var status = cenk.Status;
            MessageBox.Show($"Message: {message} | Result: {status}");

            if (status == true)
            {
                // Sucesso no login, abrindo nova janela
                box = 2;
                new Form2().Show();
                this.Hide();
            }
        }

        private void label2_Click(object sender, EventArgs e) { }

        private void label1_Click(object sender, EventArgs e) { }

        private void textBox3_TextChanged(object sender, EventArgs e) { }

        private void label3_Click(object sender, EventArgs e) { }

        private void textBox2_TextChanged(object sender, EventArgs e) { }

        private void textBox1_TextChanged(object sender, EventArgs e) { }
    }
}
//string libLoc = string.Empty;
//if (IntPtr.Size == 4)
//    libLoc = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Auth-x86.dll"); 
//else
//    libLoc = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Auth-x64.dll");
//var fileBuffer = File.ReadAllBytes(libLoc);
//var hash = Convert.ToBase64String(SHA256.Create().ComputeHash(fileBuffer));

//if (hash == "wCR48+EEOwqvOVFyk9g5I0lrmbB0vz9IRM6Fww6cahk=" ||
//    hash == "a/hfrVPvufyJ2BjLJfTM4KBin8/r46SqUlBSgamdiOM=")
//{
// var lib = LoadLibrary(libLoc);
//var callback = (Callback)Marshal.GetDelegateForFunctionPointer(GetProcAddress(lib, "Send"), typeof(Callback));
//var callback0 = (Callback)Marshal.GetDelegateForFunctionPointer(GetProcAddress(lib, "Send"), typeof(Callback));
//var methodPtr = Marshal.StringToHGlobalAnsi("login");
//var usernamePtr = Marshal.StringToHGlobalAnsi(textBox1.Text);
//var passwordPtr = Marshal.StringToHGlobalAnsi(textBox2.Text);
//var hwidPtr = Marshal.StringToHGlobalAnsi(textBox3.Text);
//callback(methodPtr, usernamePtr, passwordPtr, hwidPtr, out IntPtr messagePtr, out bool result);

//    try
//    {

//        var message = Marshal.PtrToStringAnsi(messagePtr);
//    MessageBox.Show($"Message: {message} | Result: {result}");

//    }
//    finally
//{
//    Marshal.FreeHGlobal(methodPtr);
//    Marshal.FreeHGlobal(usernamePtr);
//    Marshal.FreeHGlobal(passwordPtr);
//    Marshal.FreeHGlobal(hwidPtr);
//        if (result == true)
//        {
//            box = 2;
//            new Form2().Show();
//            base.Hide();
//        }
//        else { }
//}
//}
//else
//{
//    MessageBox.Show("Message: Auth library hash check failed!");
//}

//Console.ReadKey();