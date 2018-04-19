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

namespace libsignal.ecc
{
    public class EcKeyPair
    {

        private readonly IEcPublicKey _publicKey;
        private readonly IEcPrivateKey _privateKey;

        public EcKeyPair(IEcPublicKey publicKey, IEcPrivateKey privateKey)
        {
            this._publicKey = publicKey;
            this._privateKey = privateKey;
        }

        public IEcPublicKey GetPublicKey()
        {
            return _publicKey;
        }

        public IEcPrivateKey GetPrivateKey()
        {
            return _privateKey;
        }
    }
}