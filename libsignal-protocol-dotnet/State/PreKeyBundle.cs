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
    /// <summary>    
    /// A class that contains a remote PreKey and collection  of associated items.  
    /// </summary>
    /// <author>Moxie Marlinspike</author>
    public class PreKeyBundle
    {
        private readonly uint _registrationId;
        private readonly uint _deviceId;
        private readonly uint _preKeyId;
        private readonly IEcPublicKey _preKeyPublic;
        private readonly uint _signedPreKeyId;
        private readonly IEcPublicKey _signedPreKeyPublic;
        private readonly byte[] _signedPreKeySignature;
        private readonly IdentityKey _identityKey;

        public PreKeyBundle(uint registrationId, uint deviceId, uint preKeyId, IEcPublicKey preKeyPublic,
                            uint signedPreKeyId, IEcPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                            IdentityKey identityKey)
        {
            _registrationId = registrationId;
            _deviceId = deviceId;
            _preKeyId = preKeyId;
            _preKeyPublic = preKeyPublic;
            _signedPreKeyId = signedPreKeyId;
            _signedPreKeyPublic = signedPreKeyPublic;
            _signedPreKeySignature = signedPreKeySignature;
            _identityKey = identityKey;
        }

        /// <summary>
        /// The device ID this PreKey belongs to.
        /// </summary>
        /// <returns></returns>
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
