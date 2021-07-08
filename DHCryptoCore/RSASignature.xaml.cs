using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace DHCryptoCore
{
    /// <summary>
    /// Interaction logic for RSASignature.xaml
    /// </summary>
    public partial class RSASignature : Window
    {
        private RSA rsaProcessor = new RSA();


        public RSASignature()
        {
            InitializeComponent();
        }

        private void produceKeyButton_Click(object sender, RoutedEventArgs e)
        {
            if(rsaProcessor.SaveKeyFile())
            {
                MessageBox.Show("Key files are created successfully in current directory", "Info", MessageBoxButton.OK);
            }
            else
            {
                MessageBox.Show("Fail to create key files in current directory", "Warning", MessageBoxButton.OK);
            }
        }

        private void showKeyButton_Click(object sender, RoutedEventArgs e)
        {
            rsaProcessor.GetKeyString();
            showPrivateKeyBox.Text = rsaProcessor.PrivateKey;
            showPublicKeyBox.Text = rsaProcessor.PublicKey;

        }

        private void encryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (inputEncryptStringBox.Text != "")
            {
                showEncryptStringBox.Text = "";
                try
                {
                    showEncryptStringBox.Text = rsaProcessor.RSAEncrypt(rsaProcessor.PublicKey, inputEncryptStringBox.Text);

                }
                catch
                {
                    MessageBox.Show("Fail to encrypt data", "Warning", MessageBoxButton.OK);
                }
            }
            else
            {
                MessageBox.Show("Please input your encryption data", "Warning", MessageBoxButton.OK);
            }
            
        }

        private void decryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (inputDecryptStringBox.Text != "")
            {
                showDecryptStringBox.Text = "";
                try
                {
                    showDecryptStringBox.Text = rsaProcessor.RSADecrypt(rsaProcessor.PrivateKey, inputDecryptStringBox.Text);

                }
                catch
                {
                    MessageBox.Show("Fail to decrypt data", "Warning", MessageBoxButton.OK);
                }
            }
            else
            {
                MessageBox.Show("Please input your decryption data", "Warning", MessageBoxButton.OK);
            }
        }
    }
}
