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

using Libsignal.Util;

namespace Libsignal.Kdf2
{
    public class DerivedMessageSecrets
    {

        public static readonly int Size = 80;
        private static readonly int CipherKeyLength = 32;
        private static readonly int MacKeyLength = 32;
        private static readonly int IvLength = 16;

        private readonly byte[] _cipherKey;
        private readonly byte[] _macKey;
        private readonly byte[] _iv;

        public DerivedMessageSecrets(byte[] okm)
        {
            //try
            //{
            byte[][] keys = ByteUtil.Split(okm, CipherKeyLength, MacKeyLength, IvLength);

            this._cipherKey = keys[0];
            this._macKey = keys[1];
            this._iv = keys[2];
            /*}
            catch (ParseException e)
            {
                throw new AssertionError(e);
            }*/
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
    }
}
