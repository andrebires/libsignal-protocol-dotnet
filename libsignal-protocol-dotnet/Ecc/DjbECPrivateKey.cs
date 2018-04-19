﻿/** 
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

namespace Libsignal.Ecc
{
    public class DjbEcPrivateKey : IEcPrivateKey
    {

        private readonly byte[] _privateKey;

        public DjbEcPrivateKey(byte[] privateKey)
        {
            this._privateKey = privateKey;
        }


        public byte[] Serialize()
        {
            return _privateKey;
        }


        public int GetKeyType()
        {
            return Curve.DjbType;
        }

        public byte[] GetPrivateKey()
        {
            return _privateKey;
        }
    }
}
