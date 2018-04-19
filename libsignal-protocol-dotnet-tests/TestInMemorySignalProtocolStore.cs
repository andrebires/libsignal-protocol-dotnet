/** 
 * Copyright (C) 2016 langboost
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

using libsignal;
using libsignal.ecc;
using libsignal.state.impl;
using libsignal.util;

namespace libsignal_test
{
    class TestInMemorySignalProtocolStore : InMemorySignalProtocolStore
    {
        public TestInMemorySignalProtocolStore()
            : base(GenerateIdentityKeyPair(), GenerateRegistrationId())
        { }

        private static IdentityKeyPair GenerateIdentityKeyPair()
        {
            EcKeyPair identityKeyPairKeys = Curve.GenerateKeyPair();

            return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.GetPublicKey()),
                                                       identityKeyPairKeys.GetPrivateKey());
        }

        private static uint GenerateRegistrationId()
        {
            return KeyHelper.GenerateRegistrationId(false);
        }
    }
}
