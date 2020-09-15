using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace EasyRSA
{
    /// <summary>
    /// (c) 2020 maurictg, job79
    /// This class is able to generate strong RSA keys, even from a seed
    /// </summary>
    public class RsaKey
    {
        public RSAParameters Parameters { get; }
        public bool IsPrivate { get; } = true;

        /// <summary>
        /// Get RsaKey with only public information
        /// </summary>
        public RsaKey PublicKey => new RsaKey(new RSAParameters { Exponent = Parameters.Exponent, Modulus = Parameters.Modulus }, KeySize);

        /// <summary>
        /// Returns KeySize in bits
        /// </summary>
        public int KeySize { get; }
        
        /// <summary>
        /// Create new RSAKey object from generated RSAParameters
        /// </summary>
        /// <param name="parameters">Generated parameters</param>
        /// <param name="keySize">The keySize. This must match the parameters</param>
        private RsaKey(RSAParameters parameters, int keySize)
        {
            Parameters = parameters;
            KeySize = keySize;
            IsPrivate = (parameters.D != null);
        }
        
        /// <summary>
        /// Create new random RSAKey
        /// </summary>
        /// <param name="keySize">The keysize (default = 1024)</param>
        public RsaKey(int keySize = 1024) : this(new RSACryptoServiceProvider(keySize)) {}
        
        /// <summary>
        /// Create RSAKey object from CryptoServiceProvider
        /// </summary>
        /// <param name="csp">The created RSACryptoServiceProvider</param>
        public RsaKey(RSACryptoServiceProvider csp) : this(csp.ExportParameters(!csp.PublicOnly), csp.KeySize){}

        /// <summary>
        /// Create RsaKey from PEM format
        /// </summary>
        /// <param name="pem">The PEM string</param>
        /// <param name="isPrivate">Indicates if it contains the private parameters</param>
        /// <returns>RsaKey</returns>
        public static RsaKey Create(string pem, bool isPrivate)
            => new RsaKey((isPrivate) ? PemHelper.ImportPrivateKey(pem) : PemHelper.ImportPublicKey(pem));

        
        /// <summary>
        /// Create RsaKey from XML
        /// </summary>
        /// <param name="xml">The XML string</param>
        /// <returns>RsaKey</returns>
        public static RsaKey Create(string xml)
        {
            using var csp = new RSACryptoServiceProvider();
            csp.FromXmlString(xml);
            return new RsaKey(csp);
        }

        /// <summary>
        /// Create RSAKey with a seed
        /// </summary>
        /// <param name="keySize">The size of the key. Default is 1024</param>
        /// <param name="seed">The seed for the random generator. It will be hashed with SHA-256</param>
        /// <returns>A RSAKey object</returns>
        public static RsaKey Create(int keySize = 1024, byte[] seed = null)
        {
            //Check if keySize is valid for the RSACtyptoServiceProvider
            using var csp = new RSACryptoServiceProvider();
            foreach (var sizes in csp.LegalKeySizes)
            {
                if (keySize >= sizes.MinSize && keySize <= sizes.MaxSize)
                {
                    if(keySize % sizes.SkipSize != 0)
                        throw new ArgumentException("Keysize is invalid");
                }
                else
                    throw new ArgumentException("Key is not in the legal keysize range");
            }
            csp.Dispose();

            if (seed == null || seed.Length == 0)
            {
                seed = new byte[32];
                using var rng = new RNGCryptoServiceProvider();
                rng.GetBytes(seed);
            }
            
            //Hash seed
            using var sha256 = new SHA256CryptoServiceProvider();
            byte[] _seed = sha256.ComputeHash(seed);

            //IGNORE obsolete warning please, else it doesnt work for some reason
            RsaKeyPairGenerator g = new RsaKeyPairGenerator();
            g.Init(new KeyGenerationParameters(new SecureRandom(_seed), keySize));
            
            var parameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)g.GenerateKeyPair().Private);
            return new RsaKey(parameters, keySize);
        }

        public override string ToString() => ToPemString(true);
        public string ToXmlString(bool withPrivate)
        {
            using var csp = new RSACryptoServiceProvider();
            csp.ImportParameters(Parameters);
            return csp.ToXmlString(withPrivate && IsPrivate);
        }

        public string ToPemString(bool withPrivate)
        {
            using var csp = new RSACryptoServiceProvider();
            csp.ImportParameters(Parameters);
            return (withPrivate) ? PemHelper.ExportPrivateKey(csp) : PemHelper.ExportPublicKey(csp);
        }
        
    }
}