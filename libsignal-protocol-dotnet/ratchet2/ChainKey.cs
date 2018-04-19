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

using libsignal.kdf;
using libsignal.util;
using System;
using System.Text;

namespace libsignal.ratchet
{
    public class ChainKey
    {

        private static readonly byte[] MessageKeySeed = { 0x01 };
        private static readonly byte[] ChainKeySeed = { 0x02 };

        private readonly Hkdf _kdf;
        private readonly byte[] _key;
        private readonly uint _index;

        public ChainKey(Hkdf kdf, byte[] key, uint index)
        {
            this._kdf = kdf;
            this._key = key;
            this._index = index;
        }

        public byte[] GetKey()
        {
            return _key;
        }

        public uint GetIndex()
        {
            return _index;
        }

        public ChainKey GetNextChainKey()
        {
            byte[] nextKey = GetBaseMaterial(ChainKeySeed);
            return new ChainKey(_kdf, nextKey, _index + 1);
        }

        public MessageKeys GetMessageKeys()
        {
            byte[] inputKeyMaterial = GetBaseMaterial(MessageKeySeed);
            byte[] keyMaterialBytes = _kdf.DeriveSecrets(inputKeyMaterial, Encoding.UTF8.GetBytes("WhisperMessageKeys"), DerivedMessageSecrets.Size);
            DerivedMessageSecrets keyMaterial = new DerivedMessageSecrets(keyMaterialBytes);

            return new MessageKeys(keyMaterial.GetCipherKey(), keyMaterial.GetMacKey(), keyMaterial.GetIv(), _index);
        }

        private byte[] GetBaseMaterial(byte[] seed)
        {
            try
            {
                return Sign.Sha256Sum(_key, seed);
            }
            catch (InvalidKeyException e)
            {
                throw new Exception(e.Message);
            }
        }
    }
}
