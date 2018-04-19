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

using System.Diagnostics;
using Libsignal.Ecc;
using Libsignal.Protocol;
using Libsignal.Ratchet;
using Libsignal.State;
using Strilanc.Value;

namespace Libsignal
{

    /// <summary>
    ///  SessionBuilder is responsible for setting up encrypted sessions.
    ///  Once a session has been established, {@link org.whispersystems.libsignal.SessionCipher}
    ///  can be used to encrypt/decrypt messages in that session.
    /// 
    ///  Sessions are built from one of three different possible vectors:
    ///  - A <see cref="PreKeyBundle"/> retrieved from a server.
    ///  - A <see cref="PreKeySignalMessage"/> received from a client.
    ///  
    ///  Sessions are constructed per recipientId + deviceId tuple.  Remote logical users are identified
    ///  by their recipientId, and each logical recipientId can have multiple physical devices.
    ///  
    ///  @author Moxie Marlinspike       
    /// </summary>
    public class SessionBuilder
    {

        private readonly ISessionStore _sessionStore;
        private readonly IPreKeyStore _preKeyStore;
        private readonly ISignedPreKeyStore _signedPreKeyStore;
        private readonly IDentityKeyStore _identityKeyStore;
        private readonly SignalProtocolAddress _remoteAddress;

        /**
         * Constructs a SessionBuilder.
         *
         * @param sessionStore The {@link org.whispersystems.libsignal.state.SessionStore} to store the constructed session in.
         * @param preKeyStore The {@link  org.whispersystems.libsignal.state.PreKeyStore} where the client's local {@link org.whispersystems.libsignal.state.PreKeyRecord}s are stored.
         * @param identityKeyStore The {@link org.whispersystems.libsignal.state.IdentityKeyStore} containing the client's identity key information.
         * @param remoteAddress The address of the remote user to build a session with.
         */
        public SessionBuilder(ISessionStore sessionStore,
                              IPreKeyStore preKeyStore,
                              ISignedPreKeyStore signedPreKeyStore,
                              IDentityKeyStore identityKeyStore,
                              SignalProtocolAddress remoteAddress)
        {
            _sessionStore = sessionStore;
            _preKeyStore = preKeyStore;
            _signedPreKeyStore = signedPreKeyStore;
            _identityKeyStore = identityKeyStore;
            _remoteAddress = remoteAddress;
        }

        /**
         * Constructs a SessionBuilder
         * @param store The {@link SignalProtocolStore} to store all state information in.
         * @param remoteAddress The address of the remote user to build a session with.
         */
        public SessionBuilder(ISignalProtocolStore store, SignalProtocolAddress remoteAddress)
            : this(store, store, store, store, remoteAddress)
        {
        }

        /**
         * Build a new session from a received {@link PreKeySignalMessage}.
         *
         * After a session is constructed in this way, the embedded {@link SignalMessage}
         * can be decrypted.
         *
         * @param message The received {@link PreKeySignalMessage}.
         * @throws org.whispersystems.libsignal.InvalidKeyIdException when there is no local
         *                                                             {@link org.whispersystems.libsignal.state.PreKeyRecord}
         *                                                             that corresponds to the PreKey ID in
         *                                                             the message.
         * @throws org.whispersystems.libsignal.InvalidKeyException when the message is formatted incorrectly.
         * @throws org.whispersystems.libsignal.UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
         */
        /*package*/
        internal May<uint> Process(SessionRecord sessionRecord, PreKeySignalMessage message)
        {
            uint messageVersion = message.GetMessageVersion();
            IdentityKey theirIdentityKey = message.GetIdentityKey();

            if (!_identityKeyStore.IsTrustedIdentity(_remoteAddress, theirIdentityKey, Direction.Receiving))
            {
                throw new UntrustedIdentityException(_remoteAddress.Name, theirIdentityKey);
            }

            May<uint> unsignedPreKeyId = ProcessV3(sessionRecord, message);

            _identityKeyStore.SaveIdentity(_remoteAddress, theirIdentityKey);
            return unsignedPreKeyId;
        }

        private May<uint> ProcessV3(SessionRecord sessionRecord, PreKeySignalMessage message)
        {

            if (sessionRecord.HasSessionState(message.GetMessageVersion(), message.GetBaseKey().Serialize()))
            {
                Debug.WriteLine("We've already setup a session for this V3 message, letting bundled message fall through...");
                return May<uint>.NoValue;
            }

            EcKeyPair ourSignedPreKey = _signedPreKeyStore.LoadSignedPreKey(message.GetSignedPreKeyId()).GetKeyPair();

            BobSignalProtocolParameters.Builder parameters = BobSignalProtocolParameters.NewBuilder();

            parameters.SetTheirBaseKey(message.GetBaseKey())
                      .SetTheirIdentityKey(message.GetIdentityKey())
                      .SetOurIdentityKey(_identityKeyStore.GetIdentityKeyPair())
                      .SetOurSignedPreKey(ourSignedPreKey)
                      .SetOurRatchetKey(ourSignedPreKey);

            if (message.GetPreKeyId().HasValue)
            {
                parameters.SetOurOneTimePreKey(new May<EcKeyPair>(_preKeyStore.LoadPreKey(message.GetPreKeyId().ForceGetValue()).GetKeyPair()));
            }
            else
            {
                parameters.SetOurOneTimePreKey(May<EcKeyPair>.NoValue);
            }

            if (!sessionRecord.IsFresh()) sessionRecord.ArchiveCurrentState();

            RatchetingSession.InitializeSession(sessionRecord.GetSessionState(), parameters.Create());

            sessionRecord.GetSessionState().SetLocalRegistrationId(_identityKeyStore.GetLocalRegistrationId());
            sessionRecord.GetSessionState().SetRemoteRegistrationId(message.GetRegistrationId());
            sessionRecord.GetSessionState().SetAliceBaseKey(message.GetBaseKey().Serialize());

            if (message.GetPreKeyId().HasValue)
            {
                return message.GetPreKeyId();
            }
            else
            {
                return May<uint>.NoValue;
            }
        }

        /**
         * Build a new session from a {@link org.whispersystems.libsignal.state.PreKeyBundle} retrieved from
         * a server.
         *
         * @param preKey A PreKey for the destination recipient, retrieved from a server.
         * @throws InvalidKeyException when the {@link org.whispersystems.libsignal.state.PreKeyBundle} is
         *                             badly formatted.
         * @throws org.whispersystems.libsignal.UntrustedIdentityException when the sender's
         *                                                                  {@link IdentityKey} is not
         *                                                                  trusted.
         */
        public void Process(PreKeyBundle preKey)
        {
            lock (SessionCipher.SessionLock)
            {
                if (!_identityKeyStore.IsTrustedIdentity(_remoteAddress, preKey.GetIdentityKey(), Direction.Sending))
                {
                    throw new UntrustedIdentityException(_remoteAddress.Name, preKey.GetIdentityKey());
                }

                if (preKey.GetSignedPreKey() != null &&
                    !Curve.VerifySignature(preKey.GetIdentityKey().GetPublicKey(),
                                           preKey.GetSignedPreKey().Serialize(),
                                           preKey.GetSignedPreKeySignature()))
                {
                    throw new InvalidKeyException("Invalid signature on device key!");
                }

                if (preKey.GetSignedPreKey() == null)
                {
                    throw new InvalidKeyException("No signed prekey!");
                }

                SessionRecord sessionRecord = _sessionStore.LoadSession(_remoteAddress);
                EcKeyPair ourBaseKey = Curve.GenerateKeyPair();
                IEcPublicKey theirSignedPreKey = preKey.GetSignedPreKey();
                IEcPublicKey test = preKey.GetPreKey();
                May<IEcPublicKey> theirOneTimePreKey = (test == null) ? May<IEcPublicKey>.NoValue : new May<IEcPublicKey>(test);
                May<uint> theirOneTimePreKeyId = theirOneTimePreKey.HasValue ? new May<uint>(preKey.GetPreKeyId()) :
                                                                                              May<uint>.NoValue;

                AliceSignalProtocolParameters.Builder parameters = AliceSignalProtocolParameters.NewBuilder();

                parameters.SetOurBaseKey(ourBaseKey)
                              .SetOurIdentityKey(_identityKeyStore.GetIdentityKeyPair())
                              .SetTheirIdentityKey(preKey.GetIdentityKey())
                              .SetTheirSignedPreKey(theirSignedPreKey)
                              .SetTheirRatchetKey(theirSignedPreKey)
                              .SetTheirOneTimePreKey(theirOneTimePreKey);

                if (!sessionRecord.IsFresh()) sessionRecord.ArchiveCurrentState();

                RatchetingSession.InitializeSession(sessionRecord.GetSessionState(), parameters.Create());

                sessionRecord.GetSessionState().SetUnacknowledgedPreKeyMessage(theirOneTimePreKeyId, preKey.GetSignedPreKeyId(), ourBaseKey.GetPublicKey());
                sessionRecord.GetSessionState().SetLocalRegistrationId(_identityKeyStore.GetLocalRegistrationId());
                sessionRecord.GetSessionState().SetRemoteRegistrationId(preKey.GetRegistrationId());
                sessionRecord.GetSessionState().SetAliceBaseKey(ourBaseKey.GetPublicKey().Serialize());

                _identityKeyStore.SaveIdentity(_remoteAddress, preKey.GetIdentityKey());

                _sessionStore.StoreSession(_remoteAddress, sessionRecord);
            }
        }
    }
}
