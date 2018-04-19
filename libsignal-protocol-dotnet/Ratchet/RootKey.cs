/** 
 * Copyright (C) 2016 smndtrl, langboost
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

using System.Text;
using Libsignal.Ecc;
using Libsignal.Kdf2;
using Libsignal.Util;

namespace Libsignal.Ratchet
{
    public class RootKey
    {

        private readonly Hkdf _kdf;
        private readonly byte[] _key;

        public RootKey(Hkdf kdf, byte[] key)
        {
            this._kdf = kdf;
            this._key = key;
        }

        public byte[] GetKeyBytes()
        {
            return _key;
        }

        public Pair<RootKey, ChainKey> CreateChain(IEcPublicKey theirRatchetKey, EcKeyPair ourRatchetKey)
        {
            byte[] sharedSecret = Curve.CalculateAgreement(theirRatchetKey, ourRatchetKey.GetPrivateKey());
            byte[] derivedSecretBytes = _kdf.DeriveSecrets(sharedSecret, _key, Encoding.UTF8.GetBytes("WhisperRatchet"), DerivedRootSecrets.Size);
            DerivedRootSecrets derivedSecrets = new DerivedRootSecrets(derivedSecretBytes);

            RootKey newRootKey = new RootKey(_kdf, derivedSecrets.GetRootKey());
            ChainKey newChainKey = new ChainKey(_kdf, derivedSecrets.GetChainKey(), 0);

            return new Pair<RootKey, ChainKey>(newRootKey, newChainKey);
        }
    }
}
