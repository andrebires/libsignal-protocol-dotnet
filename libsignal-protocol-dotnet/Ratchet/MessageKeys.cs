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

namespace Libsignal.Ratchet
{
    public class MessageKeys
    {

        private readonly byte[] _cipherKey;
        private readonly byte[] _macKey;
        private readonly byte[] _iv;
        private readonly uint _counter;

        public MessageKeys(byte[] cipherKey, byte[] macKey, byte[] iv, uint counter)
        {
            _cipherKey = cipherKey;
            _macKey = macKey;
            _iv = iv;
            _counter = counter;
        }

        public byte[] GetCipherKey()
        {
            return _cipherKey;
        }

        public byte[] GetMacKey()
        {
            return _macKey;
        }

        public byte[] GetIv()
        {
            return _iv;
        }

        public uint GetCounter()
        {
            return _counter;
        }
    }
}
