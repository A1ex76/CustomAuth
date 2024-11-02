using System;
using System.Text;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;

namespace AuthApi
{
    public struct Result
    {
        public string Message { get; set; }
        public bool Status { get; set; }

        public Result(string message, bool status)
        {
            Message = message;
            Status = status;
        }
    }

    public class Authenticator
    {
        public static async Task<Result> SendAsync(string method, string username, string password, string hardwareId)
        {
            string message = string.Empty;
            bool status = false;

            try
            {
                var request = new RequestData
                {
                    Method = method,
                    Username = username,
                    Password = password,
                    HardwareID = hardwareId
                };

                string postId = "AhQ7GSLB91PkyN434DOov995ZrjjRWArFdWmI8uomkTzGKjHTf";
                string webSiteAddr = "https://perfauth.xyz/api2/index.php";

                var responseData = await RequestHandler.Request(postId, webSiteAddr, request);
                message = responseData.Message;
                if (responseData.Status == "success")
                    status = true;
                else
                    status = false;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                status = false;
            }

            return new Result(message, status);
        }
    }

    class RequestData
    {
        [JsonPropertyName("Method")]
        public string Method { get; set; }

        [JsonPropertyName("Username")]
        public string Username { get; set; }

        [JsonPropertyName("Password")]
        public string Password { get; set; }

        [JsonPropertyName("HWID")]
        public string HardwareID { get; set; }
    }

    class ResponsetData
    {
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }
    }

    class RequestHandler
    {
        public static async Task<ResponsetData> Request(string postId, string indexAddr, RequestData value)
        {
            using (var httpClient = new HttpClient())
            {
                var json = JsonSerializer.Serialize(value);
                var encryptedJson = RSACrypto.RSAPublic(json, true);

                var formData = new Dictionary<string, string>
                {
                    { postId, encryptedJson }
                };

                var response = await httpClient.PostAsync(indexAddr, new FormUrlEncodedContent(formData));
                var responseString = await response.Content.ReadAsStringAsync();

                var decryptedResponse = RSACrypto.RSAPublic(responseString, false);
                if (!IsJson(decryptedResponse))
                    throw new Exception("Resposta não é um JSON válido.");

                return JsonSerializer.Deserialize<ResponsetData>(decryptedResponse);
            }
        }

        public static bool IsJson(string input)
        {
            input = input.Trim();
            return input.StartsWith("{") && input.EndsWith("}") || input.StartsWith("[") && input.EndsWith("]");
        }
    }

    class RSACrypto
    {
        static readonly char[] HexDigits = "0123456789ABCDEF".ToCharArray();
        static readonly int RSA_PKCS1_PADDING = 0x01;

        [DllImport("kernel32", EntryPoint = "LoadLibrary", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", EntryPoint = "GetProcAddress", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", EntryPoint = "FreeLibrary", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool FreeLibrary(IntPtr hModule);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate IntPtr RSAPublicNewDelegate(IntPtr pr, ref IntPtr _in, int length);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int RSASizeDelegate(IntPtr rsa);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int RSAPublicEncryptDelegate(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int RSAPublicDecryptDelegate(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int RSAFreeDelegate(IntPtr rsa);

        static IntPtr cryptoLib = IntPtr.Zero;
        static RSAPublicNewDelegate rsaNew;
        static RSASizeDelegate rsaSize;
        static RSAPublicEncryptDelegate rsaEncrypt;
        static RSAPublicDecryptDelegate rsaDecrypt;
        static RSAFreeDelegate rsaFree;

        static T GetProcAddress<T>(IntPtr hModule, string procName)
        {
            if (hModule == IntPtr.Zero)
                throw new ArgumentNullException(nameof(hModule));

            var proc = GetProcAddress(hModule, procName);
            if (proc == IntPtr.Zero)
                throw new InvalidOperationException($"Function {procName} not found in module.");

            return (T)(object)Marshal.GetDelegateForFunctionPointer(proc, typeof(T));
        }

        static IntPtr ConvertToIntPtr(byte[] buffer)
        {
            var ptr = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, ptr, buffer.Length);

            return ptr;
        }

        public static string RSAPublic(string data, bool encrypt)
        {
            var pubKey = new byte[]
            {
                0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02, 0x82,
                0x02, 0x01, 0x00, 0x8D, 0x77, 0x47, 0x38, 0xF6, 0x22, 0x91, 0x63, 0xFB, 0xC8, 0x1D, 0x83,
                0xA1, 0xAD, 0xEE, 0x34, 0xD6, 0x31, 0x00, 0x3A, 0xF4, 0x62, 0x5E, 0x1E, 0x2C, 0x62, 0xE9,
                0x05, 0xC9, 0xAA, 0x6B, 0xCA, 0x84, 0x6A, 0x3E, 0x50, 0x47, 0xB6, 0x83, 0x01, 0x44, 0x39,
                0x24, 0x63, 0x8A, 0x5D, 0x5C, 0x00, 0xC8, 0xAD, 0x7F, 0x8F, 0xAD, 0x73, 0xA3, 0x3A, 0xFB,
                0xC9, 0x1B, 0x35, 0xB7, 0x70, 0x23, 0x42, 0x41, 0x8D, 0x8A, 0xB4, 0xBA, 0xD5, 0x6E, 0xB4,
                0x1A, 0x2A, 0x2D, 0x10, 0x7A, 0xBA, 0x56, 0xD3, 0x12, 0x90, 0x4F, 0x93, 0x61, 0xA1, 0x09,
                0x03, 0xA6, 0x5A, 0x69, 0xD0, 0x14, 0x4A, 0xF8, 0x1D, 0x4F, 0x2C, 0xF6, 0x79, 0xED, 0xCA,
                0xF9, 0x6C, 0x99, 0xA9, 0x8D, 0x41, 0xA5, 0xCE, 0x2F, 0xD3, 0x8B, 0x4B, 0xF7, 0x57, 0x2B,
                0x9B, 0x64, 0xEF, 0x14, 0x9A, 0xA5, 0xB8, 0xAD, 0x13, 0x31, 0x06, 0xBE, 0xB2, 0x55, 0xC9,
                0xFE, 0x51, 0x13, 0x54, 0xE5, 0x15, 0x72, 0xCE, 0xCB, 0xA7, 0x60, 0x6E, 0xEC, 0xC8, 0x90,
                0xBB, 0xBF, 0x6D, 0x57, 0xAC, 0x29, 0x6F, 0xC4, 0xC2, 0xFB, 0x59, 0xD1, 0x70, 0x9F, 0x97,
                0xAF, 0x08, 0xFD, 0x0E, 0x0E, 0x23, 0xFA, 0x86, 0x2B, 0x08, 0xB2, 0x17, 0x23, 0x5E, 0xB6,
                0xF0, 0x67, 0xF1, 0xAA, 0x7A, 0xB7, 0x59, 0xB6, 0xE9, 0x59, 0xD2, 0x42, 0xB4, 0xDE, 0x43,
                0xEF, 0x5E, 0x8D, 0x3F, 0x5C, 0xB4, 0x8D, 0xF8, 0x44, 0x9A, 0x22, 0x47, 0xC7, 0x7B, 0xDD,
                0x91, 0xCF, 0x8B, 0x09, 0x0E, 0xD2, 0x44, 0x72, 0xBF, 0xAB, 0x86, 0x6E, 0x10, 0x9B, 0xA4,
                0xA2, 0x1B, 0xA7, 0xED, 0x89, 0xE3, 0x46, 0x31, 0x00, 0x6E, 0x93, 0x88, 0x32, 0x0D, 0x02,
                0x1D, 0x8A, 0xE1, 0xB6, 0xC4, 0xFC, 0x5C, 0xE8, 0x29, 0xF3, 0x73, 0x1D, 0xDB, 0x8F, 0x90,
                0x75, 0xA4, 0xC3, 0x22, 0xBE, 0x74, 0x38, 0xE9, 0xC8, 0xC5, 0x22, 0xA1, 0x3F, 0xFA, 0x91,
                0x6D, 0x59, 0x99, 0x84, 0xB9, 0x35, 0x0B, 0xAC, 0x60, 0x18, 0x5D, 0xA1, 0x62, 0xD8, 0xEC,
                0xED, 0xFD, 0x04, 0x1A, 0xD7, 0x96, 0x8C, 0x14, 0x65, 0xAD, 0x29, 0xB7, 0x8D, 0xB7, 0x92,
                0x67, 0xE7, 0x22, 0xAC, 0x02, 0xE3, 0xD1, 0x90, 0xBD, 0x8C, 0x05, 0x6F, 0xCA, 0x06, 0x88,
                0xF7, 0xCF, 0x6E, 0x85, 0x73, 0xF8, 0xEE, 0x13, 0xC8, 0x3D, 0xC7, 0x9F, 0xFD, 0xE6, 0xFB,
                0x5A, 0xD8, 0x41, 0x43, 0x79, 0xCA, 0x34, 0xD4, 0xB8, 0x7B, 0x63, 0x1B, 0xB0, 0x3C, 0x1F,
                0x94, 0x6B, 0x60, 0xA1, 0xDF, 0x27, 0xE9, 0x9B, 0x4C, 0x66, 0xE6, 0xDE, 0xA5, 0x32, 0x0F,
                0x1E, 0x82, 0x9A, 0x60, 0x40, 0xE3, 0xD6, 0x55, 0xD2, 0x7F, 0x75, 0xDF, 0x3D, 0x9D, 0x93,
                0x4B, 0x01, 0xCE, 0x59, 0x02, 0x3F, 0x62, 0x5E, 0x19, 0x71, 0xE3, 0x00, 0xD3, 0x03, 0xB4,
                0xFA, 0x61, 0x73, 0x3B, 0x3B, 0x65, 0x32, 0x99, 0x30, 0x53, 0xDA, 0x74, 0x0E, 0x60, 0x94,
                0xB7, 0xE1, 0xBF, 0xC5, 0xE0, 0x3E, 0xCF, 0x0D, 0x94, 0xB1, 0xDD, 0xF8, 0x30, 0x21, 0x7E,
                0xA0, 0x1A, 0x61, 0x77, 0xD2, 0x8A, 0x05, 0x8B, 0x40, 0xE0, 0xC4, 0xF1, 0xB9, 0xC1, 0xA7,
                0xD1, 0x08, 0xEF, 0x43, 0x79, 0x69, 0xCC, 0x2B, 0x8F, 0x8A, 0x08, 0x82, 0xCD, 0x01, 0xD1,
                0x94, 0x3B, 0xBC, 0x79, 0x8A, 0x0C, 0xFA, 0x48, 0xDF, 0x27, 0x49, 0x9A, 0x86, 0x01, 0x42,
                0x39, 0x1B, 0xE3, 0x3C, 0x49, 0xB6, 0x79, 0xA4, 0xE8, 0x9D, 0x64, 0xE4, 0xDF, 0x53, 0x21,
                0x3D, 0x0F, 0x74, 0xA2, 0x59, 0x02, 0x90, 0x7A, 0x7C, 0xD0, 0xA8, 0x67, 0xB2, 0xFA, 0x66,
                0x9A, 0x73, 0x12, 0x32, 0xD6, 0x91, 0xF6, 0x28, 0xC7, 0xA4, 0x8B, 0x47, 0x1B, 0x3B, 0xA4,
                0xD5, 0x44, 0xF7, 0x51, 0xDB, 0x02, 0x03, 0x01, 0x00, 0x01
            };

            if (cryptoLib == IntPtr.Zero)
            {
                cryptoLib = LoadLibrary("./libeay32.dll");
                if(cryptoLib == IntPtr.Zero)
                    throw new Exception("Failed to load the crypto library.");

                rsaNew = GetProcAddress<RSAPublicNewDelegate>(cryptoLib, "d2i_RSA_PUBKEY");
                rsaSize = GetProcAddress<RSASizeDelegate>(cryptoLib, "RSA_size");
                rsaEncrypt = GetProcAddress<RSAPublicEncryptDelegate>(cryptoLib, "RSA_public_encrypt");
                rsaDecrypt = GetProcAddress<RSAPublicDecryptDelegate>(cryptoLib, "RSA_public_decrypt");
                rsaFree = GetProcAddress<RSAFreeDelegate>(cryptoLib, "RSA_free");
            }

            var rsaKeyPtr = ConvertToIntPtr(pubKey);
            var rsa = rsaNew(IntPtr.Zero, ref rsaKeyPtr, pubKey.Length);
            if (rsa == IntPtr.Zero)
                throw new InvalidOperationException("Asymmetric public key not valid for use in specified state.");

            try
            {
                var buffer = new byte[rsaSize(rsa)];
                var resultLen = 0;
                if (encrypt)
                {
                    var encodeData = Encoding.UTF8.GetBytes(data);
                    resultLen = rsaEncrypt(encodeData.Length, encodeData, buffer, rsa, RSA_PKCS1_PADDING);
                }
                else
                {
                    var decodeData = HexStringToByteArray(data);
                    resultLen = rsaDecrypt(decodeData.Length, decodeData, buffer, rsa, RSA_PKCS1_PADDING);
                }

                if (resultLen == -1)
                    throw new OverflowException("Asymmetric operation failed.");

                Array.Resize(ref buffer, resultLen);
                
                if (encrypt)
                    return ByteArrayToHexString(buffer);
                else
                    return Encoding.UTF8.GetString(buffer);
            }
            finally
            {
                if (rsa != IntPtr.Zero)
                {
                    rsaFree(rsa);
                }
            }
        }

        private static string ByteArrayToHexString(byte[] bytes)
        {
            var result = new char[bytes.Length * 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                int b = bytes[i];
                result[i * 2] = HexDigits[b >> 4];
                result[i * 2 + 1] = HexDigits[b & 0xF];
            }

            return new string(result);
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string must have an even length");

            var result = new byte[hex.Length / 2];

            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return result;
        }
    }
}