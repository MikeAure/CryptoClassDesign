using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Xml.Linq;
using System.Windows;

namespace DHCryptoCore
{
    class RSA
    {
        private KeyProducer keyProducer;
        private string privateKey;
        private string publicKey;
        public string PublicKey
        {
            get
            {
                return publicKey;
            }
            set
            {
                publicKey = value;
            }
        }

        public string PrivateKey
        {
            get
            {
                return privateKey;
            }
            set
            {
                privateKey = value;
            }
        }

        class KeyProducer
        {
            ////// 生成公钥、私钥
            //////私钥文件保存路径，包含文件名///公钥文件保存路径，包含文件名
            public void RSAKey(string PrivateKeyPath, string PublicKeyPath)
            {
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                var pri = ParseXml(provider.ToXmlString(true));
                var pub = ParseXml(provider.ToXmlString(false));
                
                SaveKey(PrivateKeyPath, pri);//保存私钥文件
                SaveKey(PublicKeyPath, pub);//保存公钥文件
            }
            ////// 保存公钥/私钥文件
            //////公钥/私钥文件保存路径///公钥/私钥值
            public void SaveKey(string path, string key)
            {
                // var tmp = ParseXml(key);
                
                FileStream stream = new FileStream(path, FileMode.Create);
                StreamWriter sw = new StreamWriter(stream);
                sw.WriteLine(key);
                sw.Close();
                stream.Close();
            }
        }

        public void GetKeyString(string _privateKey="privatekey.xml", string _publicKey="publickey.xml")
        {
            try
            {
                PrivateKey = File.ReadAllText(_privateKey);
                PublicKey = File.ReadAllText(_publicKey);
            }
            catch(Exception e)
            {
                MessageBox.Show("Read key files from disk failed!", "Warning", MessageBoxButton.OK);
            }
        }

        public bool SaveKeyFile()
        {
            keyProducer = new KeyProducer();
            try
            {
                keyProducer.RSAKey("./privatekey.xml", "./publickey.xml");
            }
            catch(Exception e)
            {
                return false;
            }
            return true;
            
        }

        public static string ParseXml(string originText)
        {
            string res;
            XDocument doc = XDocument.Parse(originText);
            res = doc.ToString();
            return res;
        }
        ////// RSA加密
        //////公钥///需要加密的数据///RSA公钥加密后的数据
        public string RSAEncrypt(string xmlPublicKey, string m_strEncryptString)
        {
            string str2;
            try
            {
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                provider.FromXmlString(xmlPublicKey);
                byte[] bytes = new UnicodeEncoding().GetBytes(m_strEncryptString);
                str2 = Convert.ToBase64String(provider.Encrypt(bytes, false));
            }
            catch (Exception exception)
            {
                throw exception;
            }
        return str2;
        }

        ////// RSA解密
        //////私钥///需要解密的数据///解密后的数据
        public string RSADecrypt(string xmlPrivateKey, string m_strDecryptString)
        {
            string str2;
            try
            {
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                provider.FromXmlString(xmlPrivateKey);
                byte[] rgb = Convert.FromBase64String(m_strDecryptString);
                byte[] buffer2 = provider.Decrypt(rgb, false);
                str2 = new UnicodeEncoding().GetString(buffer2);
            }
            catch (Exception exception)
            {
                throw exception;
            }
            return str2;
        }

        ////// 签名
        //////私钥///需签名的数据///签名后的值
        public string SignatureFormatter(string p_strKeyPrivate, string m_strHashbyteSignature)
        {
            byte[] rgbHash = Convert.FromBase64String(m_strHashbyteSignature);
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.FromXmlString(p_strKeyPrivate);
            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("MD5");
            byte[] inArray = formatter.CreateSignature(rgbHash);
            return Convert.ToBase64String(inArray);
        }

        ////// 签名验证
        //////公钥///待验证的用户名///注册码///签名是否符合
        public bool SignatureDeformatter(string p_strKeyPublic, string p_strHashbyteDeformatter, string p_strDeformatterData)
        {
            try
                {
                    byte[] rgbHash = Convert.FromBase64String(p_strHashbyteDeformatter);
                    RSACryptoServiceProvider key = new RSACryptoServiceProvider();
                    key.FromXmlString(p_strKeyPublic);
                    RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
                    deformatter.SetHashAlgorithm("MD5");
                    byte[] rgbSignature = Convert.FromBase64String(p_strDeformatterData);
                    if (deformatter.VerifySignature(rgbHash, rgbSignature))
                    {
                        return true;
                    }
                    return false;
                }
            catch
                {
                    return false;
                }
        }
    }
}
