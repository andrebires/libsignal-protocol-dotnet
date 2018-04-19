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

using libsignal.groups.ratchet;
using libsignal.groups.state;
using libsignal.protocol;
using libsignal.util;
using System;

namespace libsignal.groups
{
    /**
     * The main entry point for Signal Protocol group encrypt/decrypt operations.
     *
     * Once a session has been established with {@link org.whispersystems.libsignal.groups.GroupSessionBuilder}
     * and a {@link org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage} has been
     * distributed to each member of the group, this class can be used for all subsequent encrypt/decrypt
     * operations within that session (ie: until group membership changes).
     *
     * @author Moxie Marlinspike
     */
    public class GroupCipher
    {

        public static readonly Object Lock = new Object();

        private readonly ISenderKeyStore _senderKeyStore;
        private readonly SenderKeyName _senderKeyId;

        public GroupCipher(ISenderKeyStore senderKeyStore, SenderKeyName senderKeyId)
        {
            this._senderKeyStore = senderKeyStore;
            this._senderKeyId = senderKeyId;
        }

        /**
         * Encrypt a message.
         *
         * @param paddedPlaintext The plaintext message bytes, optionally padded.
         * @return Ciphertext.
         * @throws NoSessionException
         */
        public byte[] Encrypt(byte[] paddedPlaintext)
        {
            lock (Lock)
            {
                try
                {
                    SenderKeyRecord record = _senderKeyStore.LoadSenderKey(_senderKeyId);
                    SenderKeyState senderKeyState = record.GetSenderKeyState();
                    SenderMessageKey senderKey = senderKeyState.GetSenderChainKey().GetSenderMessageKey();
                    byte[] ciphertext = GetCipherText(senderKey.GetIv(), senderKey.GetCipherKey(), paddedPlaintext);

                    SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyState.GetKeyId(),
                                                                             senderKey.GetIteration(),
                                                                             ciphertext,
                                                                             senderKeyState.GetSigningKeyPrivate());

                    senderKeyState.SetSenderChainKey(senderKeyState.GetSenderChainKey().GetNext());

                    _senderKeyStore.StoreSenderKey(_senderKeyId, record);

                    return senderKeyMessage.Serialize();
                }
                catch (InvalidKeyIdException e)
                {
                    throw new NoSessionException(e);
                }
            }
        }

        /**
         * Decrypt a SenderKey group message.
         *
         * @param senderKeyMessageBytes The received ciphertext.
         * @return Plaintext
         * @throws LegacyMessageException
         * @throws InvalidMessageException
         * @throws DuplicateMessageException
         */
        public byte[] Decrypt(byte[] senderKeyMessageBytes)
        {
            return Decrypt(senderKeyMessageBytes, new NullDecryptionCallback());
        }

        /**
         * Decrypt a SenderKey group message.
         *
         * @param senderKeyMessageBytes The received ciphertext.
         * @param callback   A callback that is triggered after decryption is complete,
         *                    but before the updated session state has been committed to the session
         *                    DB.  This allows some implementations to store the committed plaintext
         *                    to a DB first, in case they are concerned with a crash happening between
         *                    the time the session state is updated but before they're able to store
         *                    the plaintext to disk.
         * @return Plaintext
         * @throws LegacyMessageException
         * @throws InvalidMessageException
         * @throws DuplicateMessageException
         */
        public byte[] Decrypt(byte[] senderKeyMessageBytes, IDecryptionCallback callback)
        {
            lock (Lock)
            {
                try
                {
                    SenderKeyRecord record = _senderKeyStore.LoadSenderKey(_senderKeyId);

                    if (record.IsEmpty())
                    {
                        throw new NoSessionException("No sender key for: " + _senderKeyId);
                    }

                    SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyMessageBytes);
                    SenderKeyState senderKeyState = record.GetSenderKeyState(senderKeyMessage.GetKeyId());

                    senderKeyMessage.VerifySignature(senderKeyState.GetSigningKeyPublic());

                    SenderMessageKey senderKey = GetSenderKey(senderKeyState, senderKeyMessage.GetIteration());

                    byte[] plaintext = GetPlainText(senderKey.GetIv(), senderKey.GetCipherKey(), senderKeyMessage.GetCipherText());

                    callback.HandlePlaintext(plaintext);

                    _senderKeyStore.StoreSenderKey(_senderKeyId, record);

                    return plaintext;
                }
                catch (Exception e) when (e is InvalidKeyException || e is InvalidKeyIdException)
                {
                    throw new InvalidMessageException(e);
                }
            }
        }

        private SenderMessageKey GetSenderKey(SenderKeyState senderKeyState, uint iteration)
        {
            SenderChainKey senderChainKey = senderKeyState.GetSenderChainKey();

            if (senderChainKey.GetIteration() > iteration)
            {
                if (senderKeyState.HasSenderMessageKey(iteration))
                {
                    return senderKeyState.RemoveSenderMessageKey(iteration);
                }
                else
                {
                    throw new DuplicateMessageException("Received message with old counter: " +
                                                        senderChainKey.GetIteration() + " , " + iteration);
                }
            }

			//Avoiding a uint overflow
			uint senderChainKeyIteration = senderChainKey.GetIteration();
			if ((iteration > senderChainKeyIteration) && (iteration - senderChainKeyIteration > 2000))
			{
				throw new InvalidMessageException("Over 2000 messages into the future!");
			}

			while (senderChainKey.GetIteration() < iteration)
			{
				senderKeyState.AddSenderMessageKey(senderChainKey.GetSenderMessageKey());
				senderChainKey = senderChainKey.GetNext();
			}

			senderKeyState.SetSenderChainKey(senderChainKey.GetNext());
            return senderChainKey.GetSenderMessageKey();
        }

        private byte[] GetPlainText(byte[] iv, byte[] key, byte[] ciphertext)
        {
            try
            {
                /*IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);*/

                return util.Decrypt.AesCbcPkcs5(ciphertext, key, iv);
            }
            catch (Exception e)
            {
                throw new InvalidMessageException(e);
            }
        }

        private byte[] GetCipherText(byte[] iv, byte[] key, byte[] plaintext)
        {
            try
            {
                /*IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);*/

                return util.Encrypt.AesCbcPkcs5(plaintext, key, iv);
            }
            catch (Exception e)
    {
                throw new Exception(e.Message);
            }
        }

        private  class NullDecryptionCallback : IDecryptionCallback
        {
            public void HandlePlaintext(byte[] plaintext) { }
        }

    }
}
