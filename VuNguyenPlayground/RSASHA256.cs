using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace VuNguyenPlayground;

public class RSASHA256
{
    private readonly string _partnerCode;
    private readonly long _timestamp;
    private readonly Dictionary<string, string> _body;
    private static string publicPartnerKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAijAxEekuBDFdKnLCs/BzOGdbtXZATF4kZLoD8WslNxE2ysaVmHTxcFGc/kSueLvl2RwAWiCi3MQ8h2kOYrylOk2ZM7tBQbV+0Vw9JSTzybZwulJ0ibfncxXLETgB+1Koxa+HkmIn2MeYjeYvOK0Fbxx/Mvmr2QEP9oa3f25bvnrZrh88Wda4WiNxAcWqtciP4D8o50dBIJYxla/njFsv5qVeDXZ+EvXwk1QIW8MKSyZ5BBb+SlsmXXx0qTQtMkFqbWmD/8XXE21+BDELHj+eb7dYZ2MvzC7dkXHV703KhjWzKe0TBQsJyHxpmYBl5IPp0HYPcqVe0c5KbX62ZqW+rQIDAQAB";

    private static string privatePartnerKey = "MIIEpAIBAAKCAQEAijAxEekuBDFdKnLCs/BzOGdbtXZATF4kZLoD8WslNxE2ysaV\nmHTxcFGc/kSueLvl2RwAWiCi3MQ8h2kOYrylOk2ZM7tBQbV+0Vw9JSTzybZwulJ0\nibfncxXLETgB+1Koxa+HkmIn2MeYjeYvOK0Fbxx/Mvmr2QEP9oa3f25bvnrZrh88\nWda4WiNxAcWqtciP4D8o50dBIJYxla/njFsv5qVeDXZ+EvXwk1QIW8MKSyZ5BBb+\nSlsmXXx0qTQtMkFqbWmD/8XXE21+BDELHj+eb7dYZ2MvzC7dkXHV703KhjWzKe0T\nBQsJyHxpmYBl5IPp0HYPcqVe0c5KbX62ZqW+rQIDAQABAoIBAEvxEAZ3zwIe3sRl\nLPsWOTvWEWA4DD3rvrRcRa5244zPuPzXBX8zRTwkndJejENtf3NBIDBnnxkT/u+r\nnGxGn8bavkbfsY0a4QbNWgz/sbo4uNqsVb8ZgeiNIXvk+7HSS03YmPipWJyZlAzn\nYywSadoWHxE0hGxNWShyAIXXcDPNIM4A0r5L9IqmgxcE4URYKJdbatFsQuG8gFfO\nHJQOOWpS3J7ByGouPmuK/gpe/jTUbx3MsRqMAi8QcDYDQ8i0maXkFf923GEV3Cm9\nUj9Q7bL0UHXRYFGLl1t2BI8vFF7ez6L+QY6V8ig0KzTTeygW7QWdWq6sDP+eIDrM\nMy6dxUECgYEAw9Y5jszCaD5I70H2RJRji+MYWcoZRjf45jhNJ0FWupbAGyNLx/cR\nseBHkaCObkHhWh7iqXQMFTaRlmIpxsyFMbnGOIn+bc1A8mBgY2fdeBRXabciTm3r\nexAwrZ+FXk7zulYqjinzyCs7lpuWeVOInhc7YZf39BV3dK5dEHcYPWcCgYEAtKQj\nxIe+UKFni28B1b654Lyjx6Fk4Th0kLUxtBvbiM/6l75kqUlVzBtFCCZ4q9EvB5C8\nISdNnJ3bhS7n3voW9YcvxvFPHgs/VHwrqlogxyO/cGEWE0YRgkxj2BjTqA0K0yuv\nm5+sAZlXboG7oyFJY9u6gaR+0c2pD5IB0aTTwssCgYEAtz3Z+X4qYfP1trnXvu/B\n/YBupoVuBMAWywPfXV3L0yd/dWUfYWoTSob7MI4094H5ZKQFnl0ReT/oFfif8n4o\nGxEjIoAsa31kyeXYCuuC1Prjl+1d0lkTv8C0a6EZ39asQ6yggQlMK/4X8aJ/t+Kr\nsJE4ZOcXgXIcpjcIqYFmUv0CgYAhG+SiZO7xAGRmHhaMAsU299xc/qvqy9oxm8Rc\naq62SMh5f6AblyFuo6DneYWsmE6yaEjTGs0S46wUoSBGsjf7EKglIp2JuC4HYiru\nsk5Hsbmo82KEbddPtoimVwaUSq+tPNiXAZEZSe3Ih2bI45T8BI4OrQPBmJxgCjbj\nIf7eOQKBgQCi4cQfNRyD3poalfwRHrAqEHcY+dNGxwS/H+C9cxDupFO8vHYD8rCo\n13N4BrkAxAosJ/yQbOCZTKb0KxqI1tUE7DTdaC+qWIAJohr3wyt2pfE6d7g5w4SW\nZI7BOHJ7DHjieZnNz7LvTf+FFcoR/HZ5cxOGj8ScCRYo+neKD12fZQ==";
    // If we integrate other banking , 
    private static readonly string publicNashFlowKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNxLfDkx7svmhEG7iH4A5Uy8TznlxJHtgH28ETwjSoj1LJRcmAPoj6GgHs2ZUvrGwyhwKoP8II6FaSwjlssGpVP+EU030ezjdF+w2mhoKJ9xOG14mORmAoS+F/UCrLFFcZTVpQDzscCqhuXrdOl1sUlluuNAj1LLsDIs3YnMr3Lup4iUUq8L8zODWt7j/ecJnpsbOoVvfI0prbitUwOZgjob5P4VzNmB0AHHuyJQyJef6UXzEIc8uT/V6UoW3kTRV+rzOUcdex8aivSWv0gIzgEYE66V9zCtiDzJ1HuaakeV9jO1HavD/vtLGLzMI4ZlqboKinPEsFIMQ2XakA8X/wIDAQAB"; 
    private static readonly string privateNashFlowKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC83Et8OTHuy+aEQbuIfgDlTLxPOeXEke2AfbwRPCNKiPUslFyYA+iPoaAezZlS+sbDKHAqg/wgjoVpLCOWywalU/4RTTfR7ON0X7DaaGgon3E4bXiY5GYChL4X9QKssUVxlNWlAPOxwKqG5et06XWxSWW640CPUsuwMizdicyvcu6niJRSrwvzM4Na3uP95wmemxs6hW98jSmtuK1TA5mCOhvk/hXM2YHQAce7IlDIl5/pRfMQhzy5P9XpShbeRNFX6vM5Rx17HxqK9Ja/SAjOARgTrpX3MK2IPMnUe5pqR5X2M7Udq8P++0sYvMwjhmWpugqKc8SwUgxDZdqQDxf/AgMBAAECggEAB/YWuIXbX6r4wgUuAp2igV1avXw9/gCozQx/1mTSmAcYpBMc/suAt41N/VPCwty6GZVQJSVV24l71j3Qwj/iEoDClQ127O0vfsMJ5tW/46EqWgFDXtlB85k6P4hJ3z3Eek/r3FN4nRBMyqL76fxtbwEeaLfBC578jHuQ/fBxJcl/7sq7KRPraIAg4Z6FjzApOR5QmJxijij5nsCiGyS/MfLRoC/qFMYH8SyGNGF74AvUFA2HOT7xpivxqpTQOHOqt0OK2izMjK6WDlZQPWW4oHnHJcKIegQ+WugJj5CY5Lou1sUhxBE3UoL3I4SLmQzi3OQy9QB7RoIJk/5XE9R6AQKBgQDL+SWXq+D8cNiahCiytYnzdoTkY2oCB0M0OY7Wbm5utP07u/Sew6HtWIfljFKefLR9zZCGQzy7fwOt4DYRaO8jAke/0Ej1Q9lPd8Vjz/HMKVYLkCWxnvX85uleM3ruglC4YoBUYSOP3XRy6jZ+Qjuc5/pBlxlIYW/4yi53RmxK9wKBgQDtCFU3HASAhT1gRnVHu/j4ofO1NcfcLBDl6VRDBY3I0nzKoXsre15uu8HZNAeEr/3uuLfW7FlPVSUw0h1mFRkYEhejUBFNZDO/f8CgzK8hYbooO3i/GsHSUKv2yRSk/O4iLwIni1Q+qHsT39noS7/LzfG2zPsT4G3t2Vj04MgROQKBgBfaWvsRro3W5H2tVtUPRcKi6YeL2KnED6fb00hgQanQoIyLvl+SoS0QXVQKxN6j1refgncxBbkncVa0EZ6Xlt+RNLLJuL514MPaTcsOVkh5zQYtJTtQS5P3rPLHMmkR9D6bxkYX1gDM9QE7QoQhWrdOqYViFiLQwjdl7WklYyShAoGBAJAqJUojbEmOwEmyENrUZRUzyzpHv4sV8iEjzPAGjLm769KCbJuBqWnIIJqunnQBZnyvNIEvtxIdQ0VyRhc0ddLCDkZyCFP9wcuTM+GZHFs9SS/3G/V/nKsCDdVHb5r5iwyXcsQCZfbGGjV4TNyQVdLrKzx3Z64rLjEfpI8ruANhAoGBAJi64hksDEJJBRHIxWUit3lN2w5xUa8Rn+a6X6R+JlyK3av859UxeRmoKwkd5gZNknOjwTG6AwVpMPb7NUtKULKlJEkC6dqZoN6ZgScS9TFdTKRV9zh54n/x+nX1cn5NoHIIAetN6/cWq00GaRSQJmMkhRs8jddVjJa96wPHEn9N"; 
    
    public RSASHA256()
    {
        _partnerCode = "";
        _timestamp = 0;
        _body = new Dictionary<string, string>();
    }
    
    public RSASHA256(string partnerCode, long timestamp, Dictionary<string, string>? body) 
    {
        _partnerCode = partnerCode;
        _timestamp = timestamp;
        _body = body ?? new Dictionary<string, string>();
    }
    
    public static RSASHA256 Import(string partnerCode, long timestamp, Dictionary<string, string>? body)
    {
        return new RSASHA256(partnerCode, timestamp, body);    
    }
    
    public (string blockData, string blockSign) HashBlock()
    {
        byte[] blockData;
        using (var sha256 = SHA256.Create())
        {
            var data = _partnerCode + _timestamp;
            data = _body is null
                ? data
                : data + _body.Aggregate("", (current, item) => current + item.Key + item.Value);
            
            blockData = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
        }
        
        if(_body is not null)
        {
            Console.WriteLine(publicPartnerKey);
            var certBytes = Convert.FromBase64String(publicPartnerKey);
            var cert = new X509Certificate();
            // var aaa = cert.PublicKey
            var rsa = cert.GetRSAPublicKey();
            byte[] blockSign = rsa.Encrypt(blockData, RSAEncryptionPadding.OaepSHA256);
            
            // using (var rsa = new RSACryptoServiceProvider(2048))
            // {
            //     rsa.ImportRSAPublicKey(Convert.FromBase64String(publicPartnerKey), out _);
            //     rsa.Encrypt(blockData, blockSign, RSAEncryptionPadding.OaepSHA256);
            // }
            
            return (Convert.ToBase64String(blockData), Convert.ToBase64String(blockSign));
        }
        
        return (Convert.ToBase64String(blockData), "");
    }

    public bool Verify(string blockData, string? blockSign)
    {
        if (_timestamp < DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds())
        {
            return false;
        }
        
        // get the privateKey from partner-code => 
        if (blockSign is null)
        {
            return VerifyBlockData(blockData);
        }

        return VerifyBlockSign(blockData, blockSign);
    }
    
    private bool VerifyBlockSign(string hashedBlockData, string hashedBlockSign)
    {
        var (blockData, blockSign) = HashBlock();
        if (blockData != hashedBlockData)
        {
            return false;
        }
        
        var blockSignBytes = Convert.FromBase64String(hashedBlockSign);
        var certBytes = Convert.FromBase64String(privatePartnerKey);
        var cert = new X509Certificate2(certBytes);
        var rsa = cert.GetRSAPrivateKey();
        byte[] decryptedBlockSign = rsa.Decrypt(blockSignBytes, RSAEncryptionPadding.OaepSHA256);
        // Span<byte> decryptedBlockSign = null;
        // // Decrypt blockSign
        // using (var rsa = new RSACryptoServiceProvider(2048))
        // {
        //     rsa.ImportRSAPrivateKey(Convert.FromBase64String(privatePartnerKey), out _);
        //     rsa.Decrypt(blockSignBytes, decryptedBlockSign, RSAEncryptionPadding.OaepSHA256);
        // }

        return decryptedBlockSign == Convert.FromBase64String(hashedBlockData);
    }

    private bool VerifyBlockData(string hashedblockData)
    {
        var (blockData, blockSign) = HashBlock();
        return hashedblockData.Equals(blockData, StringComparison.InvariantCultureIgnoreCase);
    }
}