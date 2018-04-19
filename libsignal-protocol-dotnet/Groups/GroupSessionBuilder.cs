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

using System;
using Libsignal.Groups.State;
using Libsignal.Protocol;
using Libsignal.Util;

namespace Libsignal.Groups
{
    /**
     * GroupSessionBuilder is responsible for setting up group SenderKey encrypted sessions.
     *
     * Once a session has been established, {@link org.whispersystems.libsignal.groups.GroupCipher}
     * can be used to encrypt/decrypt messages in that session.
     * <p>
     * The built sessions are unidirectional: they can be used either for sending or for receiving,
     * but not both.
     *
     * Sessions are constructed per (groupId + senderId + deviceId) tuple.  Remote logical users
     * are identified by their senderId, and each logical recipientId can have multiple physical
     * devices.
     *
     * @author
     */

    public class GroupSessionBuilder
    {

        private readonly ISenderKeyStore _senderKeyStore;

        public GroupSessionBuilder(ISenderKeyStore senderKeyStore)
        {
            this._senderKeyStore = senderKeyStore;
        }

        /**
         * Construct a group session for receiving messages from senderKeyName.
         *
         * @param senderKeyName The (groupId, senderId, deviceId) tuple associated with the SenderKeyDistributionMessage.
         * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
         */
        public void Process(SenderKeyName senderKeyName, SenderKeyDistributionMessage senderKeyDistributionMessage)
        {
            lock (GroupCipher.Lock)
            {
                SenderKeyRecord senderKeyRecord = _senderKeyStore.LoadSenderKey(senderKeyName);
                senderKeyRecord.AddSenderKeyState(senderKeyDistributionMessage.GetId(),
                                                  senderKeyDistributionMessage.GetIteration(),
                                                  senderKeyDistributionMessage.GetChainKey(),
                                                  senderKeyDistributionMessage.GetSignatureKey());
                _senderKeyStore.StoreSenderKey(senderKeyName, senderKeyRecord);
            }
        }

        /**
         * Construct a group session for sending messages.
         *
         * @param senderKeyName The (groupId, senderId, deviceId) tuple.  In this case, 'senderId' should be the caller.
         * @return A SenderKeyDistributionMessage that is individually distributed to each member of the group.
         */
        public SenderKeyDistributionMessage Create(SenderKeyName senderKeyName)
        {
            lock (GroupCipher.Lock)
            {
                try
                {
                    SenderKeyRecord senderKeyRecord = _senderKeyStore.LoadSenderKey(senderKeyName);

                    if (senderKeyRecord.IsEmpty())
                    {
                        senderKeyRecord.SetSenderKeyState(KeyHelper.GenerateSenderKeyId(),
                                                          0,
                                                          KeyHelper.GenerateSenderKey(),
                                                          KeyHelper.GenerateSenderSigningKey());
                        _senderKeyStore.StoreSenderKey(senderKeyName, senderKeyRecord);
                    }

                    SenderKeyState state = senderKeyRecord.GetSenderKeyState();

                    return new SenderKeyDistributionMessage(state.GetKeyId(),
                                                            state.GetSenderChainKey().GetIteration(),
                                                            state.GetSenderChainKey().GetSeed(),
                                                            state.GetSigningKeyPublic());

                }
                catch (Exception e) when (e is InvalidKeyIdException || e is InvalidKeyException)
                {
                    throw new Exception(e.Message);
                }
            }
        }
    }
}
