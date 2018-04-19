/** 
 * Copyright (C) 2017 smndtrl, langboost, golf1052
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace Libsignal.Ecc
{
    public class Curve
    {
        public const int DjbType = 0x05;

        public static bool IsNative()
        {
            return Curve25519.GetInstance(Curve25519ProviderType.Best).IsNative();
        }

        public static EcKeyPair GenerateKeyPair()
        {
            Curve25519KeyPair keyPair = Curve25519.GetInstance(Curve25519ProviderType.Best).GenerateKeyPair();

            return new EcKeyPair(new DjbEcPublicKey(keyPair.GetPublicKey()),
                                 new DjbEcPrivateKey(keyPair.GetPrivateKey()));
        }

        public static IEcPublicKey DecodePoint(byte[] bytes, int offset)
        {
            int type = bytes[offset] & 0xFF;

            switch (type)
            {
                case DjbType:
                    byte[] keyBytes = new byte[32];
                    System.Buffer.BlockCopy(bytes, offset + 1, keyBytes, 0, keyBytes.Length);
                    return new DjbEcPublicKey(keyBytes);
                default:
                    throw new InvalidKeyException("Bad key type: " + type);
            }
        }

        public static IEcPrivateKey DecodePrivatePoint(byte[] bytes)
        {
            return new DjbEcPrivateKey(bytes);
        }

        public static byte[] CalculateAgreement(IEcPublicKey publicKey, IEcPrivateKey privateKey)
        {
            if (publicKey.GetKeyType() != privateKey.GetKeyType())
            {
                throw new InvalidKeyException("Public and private keys must be of the same type!");
            }

            if (publicKey.GetKeyType() == DjbType)
            {
                return Curve25519.GetInstance(Curve25519ProviderType.Best)
                                 .CalculateAgreement(((DjbEcPublicKey)publicKey).GetPublicKey(),
                                                     ((DjbEcPrivateKey)privateKey).GetPrivateKey());
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + publicKey.GetKeyType());
            }
        }

        public static bool VerifySignature(IEcPublicKey signingKey, byte[] message, byte[] signature)
        {
            if (signingKey.GetKeyType() == DjbType)
            {
                return Curve25519.GetInstance(Curve25519ProviderType.Best)
                                 .VerifySignature(((DjbEcPublicKey)signingKey).GetPublicKey(), message, signature);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.GetKeyType());
            }
        }

        public static byte[] CalculateSignature(IEcPrivateKey signingKey, byte[] message)
        {
            if (signingKey.GetKeyType() == DjbType)
            {
                return Curve25519.GetInstance(Curve25519ProviderType.Best)
                                 .CalculateSignature(((DjbEcPrivateKey)signingKey).GetPrivateKey(), message);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.GetKeyType());
            }
        }

        public static byte[] CalculateVrfSignature(IEcPrivateKey signingKey, byte[] message)
        {
            if (signingKey.GetKeyType() == DjbType)
            {
                return Curve25519.GetInstance(Curve25519ProviderType.Best)
                    .CalculateVrfSignature(((DjbEcPrivateKey)signingKey).GetPrivateKey(), message);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.GetKeyType());
            }
        }

        public static byte[] VerifyVrfSignature(IEcPublicKey signingKey, byte[] message, byte[] signature)
        {
            if (signingKey.GetKeyType() == DjbType)
            {
                return Curve25519.GetInstance(Curve25519ProviderType.Best)
                    .VerifyVrfSignature(((DjbEcPublicKey)signingKey).GetPublicKey(), message, signature);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.GetKeyType());
            }
        }
    }
}
