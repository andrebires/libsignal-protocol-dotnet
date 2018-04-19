namespace Libsignal.Ecc
{
    /// <summary>
    /// Curve25519 public and private key stored together.
    /// </summary>
    public class Curve25519KeyPair
    {

        private readonly byte[] _publicKey;
        private readonly byte[] _privateKey;

        /// <summary>
        /// Create a curve 25519 keypair from a public and private keys.
        /// </summary>
        /// <param name="publicKey">32 byte public key</param>
        /// <param name="privateKey">32 byte private key</param>
        public Curve25519KeyPair(byte[] publicKey, byte[] privateKey)
        {
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        /// <summary>
        /// Curve25519 public key
        /// </summary>
        /// <returns></returns>
        public byte[] GetPublicKey()
        {
            return _publicKey;
        }

        /// <summary>
        /// Curve25519 private key
        /// </summary>
        /// <returns></returns>
        public byte[] GetPrivateKey()
        {
            return _privateKey;
        }
    }
}