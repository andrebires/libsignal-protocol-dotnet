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
using libsignal.protocol;
using libsignal.state;
using libsignal.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace libsignal_test
{
    [TestClass]
    public class SimultaneousInitiateTests
    {
        private static readonly SignalProtocolAddress BobAddress = new SignalProtocolAddress("+14151231234", 1);
        private static readonly SignalProtocolAddress AliceAddress = new SignalProtocolAddress("+14159998888", 1);

        private static readonly EcKeyPair AliceSignedPreKey = Curve.GenerateKeyPair();
        private static readonly EcKeyPair BobSignedPreKey = Curve.GenerateKeyPair();

        private static readonly uint AliceSignedPreKeyId = (uint)new Random().Next((int)Medium.MaxValue);
        private static readonly uint BobSignedPreKeyId = (uint)new Random().Next((int)Medium.MaxValue);

        [TestMethod, TestCategory("libsignal")]
        public void TestBasicSimultaneousInitiate()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = CreateAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = CreateBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, AliceAddress);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            aliceSessionBuilder.Process(bobPreKeyBundle);
            bobSessionBuilder.Process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual(CiphertextMessage.PrekeyType, messageForBob.GetMessageType());
            Assert.AreEqual(CiphertextMessage.PrekeyType, messageForAlice.GetMessageType());

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.Decrypt(new PreKeySignalMessage(messageForAlice.Serialize()));
            byte[] bobPlaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(messageForBob.Serialize()));

            Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintext));
            Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintext));

            Assert.AreEqual((uint)3, aliceStore.LoadSession(BobAddress).GetSessionState().GetSessionVersion());
            Assert.AreEqual((uint)3, bobStore.LoadSession(AliceAddress).GetSessionState().GetSessionVersion());

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage aliceResponse = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual(CiphertextMessage.WhisperType, aliceResponse.GetMessageType());

            byte[] responsePlaintext = bobSessionCipher.Decrypt(new SignalMessage(aliceResponse.Serialize()));

            Assert.AreEqual("second message", Encoding.UTF8.GetString(responsePlaintext));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual(CiphertextMessage.WhisperType, finalMessage.GetMessageType());

            byte[] finalPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(finalMessage.Serialize()));

            Assert.AreEqual("third message", Encoding.UTF8.GetString(finalPlaintext));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void TestLostSimultaneousInitiate()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = CreateAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = CreateBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, AliceAddress);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            aliceSessionBuilder.Process(bobPreKeyBundle);
            bobSessionBuilder.Process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual<uint>(messageForBob.GetMessageType(), CiphertextMessage.PrekeyType);
            Assert.AreEqual<uint>(messageForAlice.GetMessageType(), CiphertextMessage.PrekeyType);

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            byte[] bobPlaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(messageForBob.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));
            Assert.IsTrue(bobStore.LoadSession(AliceAddress).GetSessionState().GetSessionVersion() == 3);

            CiphertextMessage aliceResponse = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.GetMessageType(), CiphertextMessage.PrekeyType);

            byte[] responsePlaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(aliceResponse.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(responsePlaintext).Equals("second message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.IsTrue(finalMessage.GetMessageType() == CiphertextMessage.WhisperType);

            byte[] finalPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(finalMessage.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void TestSimultaneousInitiateLostMessage()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = CreateAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = CreateBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, AliceAddress);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            aliceSessionBuilder.Process(bobPreKeyBundle);
            bobSessionBuilder.Process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual<uint>(messageForBob.GetMessageType(), CiphertextMessage.PrekeyType);
            Assert.AreEqual<uint>(messageForAlice.GetMessageType(), CiphertextMessage.PrekeyType);

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.Decrypt(new PreKeySignalMessage(messageForAlice.Serialize()));
            byte[] bobPlaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(messageForBob.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintext).Equals("sample message"));
            Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));

            Assert.IsTrue(aliceStore.LoadSession(BobAddress).GetSessionState().GetSessionVersion() == 3);
            Assert.IsTrue(bobStore.LoadSession(AliceAddress).GetSessionState().GetSessionVersion() == 3);

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage aliceResponse = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.GetMessageType(), CiphertextMessage.WhisperType);

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual<uint>(finalMessage.GetMessageType(), CiphertextMessage.WhisperType);

            byte[] finalPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(finalMessage.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void TestSimultaneousInitiateRepeatedMessages()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = CreateAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = CreateBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, AliceAddress);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            aliceSessionBuilder.Process(bobPreKeyBundle);
            bobSessionBuilder.Process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual<uint>(messageForBob.GetMessageType(), CiphertextMessage.PrekeyType);
            Assert.AreEqual<uint>(messageForAlice.GetMessageType(), CiphertextMessage.PrekeyType);

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.Decrypt(new PreKeySignalMessage(messageForAlice.Serialize()));
            byte[] bobPlaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(messageForBob.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintext).Equals("sample message"));
            Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));

            Assert.IsTrue(aliceStore.LoadSession(BobAddress).GetSessionState().GetSessionVersion() == 3);
            Assert.IsTrue(bobStore.LoadSession(AliceAddress).GetSessionState().GetSessionVersion() == 3);

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBobRepeat.GetMessageType(), CiphertextMessage.WhisperType);
                Assert.AreEqual<uint>(messageForAliceRepeat.GetMessageType(), CiphertextMessage.WhisperType);

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.Decrypt(new SignalMessage(messageForAliceRepeat.Serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.Decrypt(new SignalMessage(messageForBobRepeat.Serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintextRepeat).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintextRepeat).Equals("hey there"));

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.GetMessageType(), CiphertextMessage.WhisperType);

            byte[] responsePlaintext = bobSessionCipher.Decrypt(new SignalMessage(aliceResponse.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(responsePlaintext).Equals("second message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual<uint>(finalMessage.GetMessageType(), CiphertextMessage.WhisperType);

            byte[] finalPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(finalMessage.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void TestRepeatedSimultaneousInitiateRepeatedMessages()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();


            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, AliceAddress);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            for (int i = 0; i < 15; i++)
            {
                PreKeyBundle alicePreKeyBundle = CreateAlicePreKeyBundle(aliceStore);
                PreKeyBundle bobPreKeyBundle = CreateBobPreKeyBundle(bobStore);

                aliceSessionBuilder.Process(bobPreKeyBundle);
                bobSessionBuilder.Process(alicePreKeyBundle);

                CiphertextMessage messageForBob = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAlice = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBob.GetMessageType(), CiphertextMessage.PrekeyType);
                Assert.AreEqual<uint>(messageForAlice.GetMessageType(), CiphertextMessage.PrekeyType);

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintext = aliceSessionCipher.Decrypt(new PreKeySignalMessage(messageForAlice.Serialize()));
                byte[] bobPlaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(messageForBob.Serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintext).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));

                Assert.IsTrue(aliceStore.LoadSession(BobAddress).GetSessionState().GetSessionVersion() == 3);
                Assert.IsTrue(bobStore.LoadSession(AliceAddress).GetSessionState().GetSessionVersion() == 3);

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));
            }

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBobRepeat.GetMessageType(), CiphertextMessage.WhisperType);
                Assert.AreEqual<uint>(messageForAliceRepeat.GetMessageType(), CiphertextMessage.WhisperType);

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.Decrypt(new SignalMessage(messageForAliceRepeat.Serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.Decrypt(new SignalMessage(messageForBobRepeat.Serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintextRepeat).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintextRepeat).Equals("hey there"));

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.GetMessageType(), CiphertextMessage.WhisperType);

            byte[] responsePlaintext = bobSessionCipher.Decrypt(new SignalMessage(aliceResponse.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(responsePlaintext).Equals("second message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual<uint>(finalMessage.GetMessageType(), CiphertextMessage.WhisperType);

            byte[] finalPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(finalMessage.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void TestRepeatedSimultaneousInitiateLostMessageRepeatedMessages()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();


            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, AliceAddress);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            //    PreKeyBundle aliceLostPreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobLostPreKeyBundle = CreateBobPreKeyBundle(bobStore);

            aliceSessionBuilder.Process(bobLostPreKeyBundle);
            //    bobSessionBuilder.process(aliceLostPreKeyBundle);

            CiphertextMessage lostMessageForBob = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
            //    CiphertextMessage lostMessageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            for (int i = 0; i < 15; i++)
            {
                PreKeyBundle alicePreKeyBundle = CreateAlicePreKeyBundle(aliceStore);
                PreKeyBundle bobPreKeyBundle = CreateBobPreKeyBundle(bobStore);

                aliceSessionBuilder.Process(bobPreKeyBundle);
                bobSessionBuilder.Process(alicePreKeyBundle);

                CiphertextMessage messageForBob = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAlice = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBob.GetMessageType(), CiphertextMessage.PrekeyType);
                Assert.AreEqual<uint>(messageForAlice.GetMessageType(), CiphertextMessage.PrekeyType);

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintext = aliceSessionCipher.Decrypt(new PreKeySignalMessage(messageForAlice.Serialize()));
                byte[] bobPlaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(messageForBob.Serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintext).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));

                Assert.IsTrue(aliceStore.LoadSession(BobAddress).GetSessionState().GetSessionVersion() == 3);
                Assert.IsTrue(bobStore.LoadSession(AliceAddress).GetSessionState().GetSessionVersion() == 3);

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));
            }

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBobRepeat.GetMessageType(), CiphertextMessage.WhisperType);
                Assert.AreEqual<uint>(messageForAliceRepeat.GetMessageType(), CiphertextMessage.WhisperType);

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.Decrypt(new SignalMessage(messageForAliceRepeat.Serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.Decrypt(new SignalMessage(messageForBobRepeat.Serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintextRepeat).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintextRepeat).Equals("hey there"));

                Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.GetMessageType(), CiphertextMessage.WhisperType);

            byte[] responsePlaintext = bobSessionCipher.Decrypt(new SignalMessage(aliceResponse.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(responsePlaintext).Equals("second message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual<uint>(finalMessage.GetMessageType(), CiphertextMessage.WhisperType);

            byte[] finalPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(finalMessage.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));

            byte[] lostMessagePlaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(lostMessageForBob.Serialize()));
            Assert.IsTrue(Encoding.UTF8.GetString(lostMessagePlaintext).Equals("hey there"));

            Assert.IsFalse(IsSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage blastFromThePast = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes("unexpected!"));
            byte[] blastFromThePastPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(blastFromThePast.Serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(blastFromThePastPlaintext).Equals("unexpected!"));
            Assert.IsTrue(IsSessionIdEqual(aliceStore, bobStore));
        }

        private bool IsSessionIdEqual(ISignalProtocolStore aliceStore, ISignalProtocolStore bobStore)
        {
            return ByteUtil.IsEqual(aliceStore.LoadSession(BobAddress).GetSessionState().GetAliceBaseKey(),
                                 bobStore.LoadSession(AliceAddress).GetSessionState().GetAliceBaseKey());
        }

        private PreKeyBundle CreateAlicePreKeyBundle(ISignalProtocolStore aliceStore)
        {
            EcKeyPair aliceUnsignedPreKey = Curve.GenerateKeyPair();
            int aliceUnsignedPreKeyId = new Random().Next((int)Medium.MaxValue);
            byte[] aliceSignature = Curve.CalculateSignature(aliceStore.GetIdentityKeyPair().GetPrivateKey(),
                                                                       AliceSignedPreKey.GetPublicKey().Serialize());

            PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
                                                              (uint)aliceUnsignedPreKeyId, aliceUnsignedPreKey.GetPublicKey(),
                                                              AliceSignedPreKeyId, AliceSignedPreKey.GetPublicKey(),
                                                              aliceSignature, aliceStore.GetIdentityKeyPair().GetPublicKey());

            aliceStore.StoreSignedPreKey(AliceSignedPreKeyId, new SignedPreKeyRecord(AliceSignedPreKeyId, (ulong)DateTime.UtcNow.Ticks, AliceSignedPreKey, aliceSignature));
            aliceStore.StorePreKey((uint)aliceUnsignedPreKeyId, new PreKeyRecord((uint)aliceUnsignedPreKeyId, aliceUnsignedPreKey));

            return alicePreKeyBundle;
        }

        private PreKeyBundle CreateBobPreKeyBundle(ISignalProtocolStore bobStore)
        {
            EcKeyPair bobUnsignedPreKey = Curve.GenerateKeyPair();
            int bobUnsignedPreKeyId = new Random().Next((int)Medium.MaxValue);
            byte[] bobSignature = Curve.CalculateSignature(bobStore.GetIdentityKeyPair().GetPrivateKey(),
                                                                     BobSignedPreKey.GetPublicKey().Serialize());

            PreKeyBundle bobPreKeyBundle = new PreKeyBundle(1, 1,
                                                            (uint)bobUnsignedPreKeyId, bobUnsignedPreKey.GetPublicKey(),
                                                            BobSignedPreKeyId, BobSignedPreKey.GetPublicKey(),
                                                            bobSignature, bobStore.GetIdentityKeyPair().GetPublicKey());

            bobStore.StoreSignedPreKey(BobSignedPreKeyId, new SignedPreKeyRecord(BobSignedPreKeyId, (ulong)DateTime.UtcNow.Ticks, BobSignedPreKey, bobSignature));
            bobStore.StorePreKey((uint)bobUnsignedPreKeyId, new PreKeyRecord((uint)bobUnsignedPreKeyId, bobUnsignedPreKey));

            return bobPreKeyBundle;
        }
    }
}
