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

using Libsignal.Ecc;

namespace Libsignal.State
{
    /**
 * A class that contains a remote PreKey and collection
 * of associated items.
 *
 * @author Moxie Marlinspike
 */
    public class PreKeyBundle
    {

        private uint _registrationId;

        private uint _deviceId;

        private uint _preKeyId;
        private IEcPublicKey _preKeyPublic;

        private uint _signedPreKeyId;
        private IEcPublicKey _signedPreKeyPublic;
        private byte[] _signedPreKeySignature;

        private IdentityKey _identityKey;

        public PreKeyBundle(uint registrationId, uint deviceId, uint preKeyId, IEcPublicKey preKeyPublic,
                            uint signedPreKeyId, IEcPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                            IdentityKey identityKey)
        {
            this._registrationId = registrationId;
            this._deviceId = deviceId;
            this._preKeyId = preKeyId;
            this._preKeyPublic = preKeyPublic;
            this._signedPreKeyId = signedPreKeyId;
            this._signedPreKeyPublic = signedPreKeyPublic;
            this._signedPreKeySignature = signedPreKeySignature;
            this._identityKey = identityKey;
        }

        /**
         * @return the device ID this PreKey belongs to.
         */
        public uint GetDeviceId()
        {
            return _deviceId;
        }

        /**
         * @return the unique key ID for this PreKey.
         */
        public uint GetPreKeyId()
        {
            return _preKeyId;
        }

        /**
         * @return the public key for this PreKey.
         */
        public IEcPublicKey GetPreKey()
        {
            return _preKeyPublic;
        }

        /**
         * @return the unique key ID for this signed prekey.
         */
        public uint GetSignedPreKeyId()
        {
            return _signedPreKeyId;
        }

        /**
         * @return the signed prekey for this PreKeyBundle.
         */
        public IEcPublicKey GetSignedPreKey()
        {
            return _signedPreKeyPublic;
        }

        /**
         * @return the signature over the signed  prekey.
         */
        public byte[] GetSignedPreKeySignature()
        {
            return _signedPreKeySignature;
        }

        /**
         * @return the {@link org.whispersystems.libsignal.IdentityKey} of this PreKeys owner.
         */
        public IdentityKey GetIdentityKey()
        {
            return _identityKey;
        }

        /**
         * @return the registration ID associated with this PreKey.
         */
        public uint GetRegistrationId()
        {
            return _registrationId;
        }
    }
}
