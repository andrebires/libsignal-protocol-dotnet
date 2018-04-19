using System;
using System.Text;
using Libsignal.Ecc;
using Libsignal.Protocol;
using Libsignal.State;
using Libsignal.State.Impl;
using Libsignal.Util;

namespace Libsignal.Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            // 1. Sender setup

            // At install time, a libsignal client needs to generate its identity keys, registration id, and prekeys.
            var senderIdentityKeyPair = KeyHelper.GenerateIdentityKeyPair();
            var senderRegistrationId = KeyHelper.GenerateRegistrationId(false);
            var senderPreKeys = KeyHelper.GeneratePreKeys(0, 100);
            var senderSignedPreKey = KeyHelper.GenerateSignedPreKey(senderIdentityKeyPair, KeyHelper.GenerateSenderKeyId());
            var senderAddress = new SignalProtocolAddress("sender", 1);

            // TODO: Store identityKeyPair somewhere durable and safe.
            // TODO: Store registrationId somewhere durable and safe.

            // Store preKeys in PreKeyStore.            
            var senderPreKeyStore = new InMemoryPreKeyStore();
            foreach (var senderPreKey in senderPreKeys)
            {
                senderPreKeyStore.StorePreKey(senderPreKey.GetId(), senderPreKey);
            }

            // Store signed prekey in SignedPreKeyStore.
            var senderSignedPreKeyStore = new InMemorySignedPreKeyStore();
            senderSignedPreKeyStore.StoreSignedPreKey(senderSignedPreKey.GetId(), senderSignedPreKey);

            var senderSessionStore = new InMemorySessionStore();
            var senderIdentityStore = new InMemoryIdentityKeyStore(senderIdentityKeyPair, senderRegistrationId);
            var senderProtocolStore = new InMemorySignalProtocolStore(senderIdentityKeyPair, senderRegistrationId);
            var senderPreKeyBundle = new PreKeyBundle(
                senderProtocolStore.GetLocalRegistrationId(),
                senderAddress.DeviceId,
                senderPreKeys[0].GetId(),
                senderPreKeys[0].GetKeyPair().GetPublicKey(),
                senderSignedPreKey.GetId(),
                senderSignedPreKey.GetKeyPair().GetPublicKey(),
                senderSignedPreKey.GetSignature(),
                senderProtocolStore.GetIdentityKeyPair().GetPublicKey()
            );

            senderProtocolStore.StorePreKey(senderPreKeys[0].GetId(), new PreKeyRecord(senderPreKeyBundle.GetPreKeyId(), senderPreKeys[0].GetKeyPair()));
            senderProtocolStore.StoreSignedPreKey(senderSignedPreKey.GetId(), new SignedPreKeyRecord(22, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), senderSignedPreKey.GetKeyPair(), senderSignedPreKey.GetSignature()));


            // 2. Destination setup
            var destinationIdentityKeyPair = KeyHelper.GenerateIdentityKeyPair();
            var destinationRegistrationId = KeyHelper.GenerateRegistrationId(false);
            var destinationPreKeys = KeyHelper.GeneratePreKeys(0, 100);
            var destinationSignedPreKey = KeyHelper.GenerateSignedPreKey(destinationIdentityKeyPair, KeyHelper.GenerateSenderKeyId());
            var destinationAddress = new SignalProtocolAddress("destination", 1);

            // TODO: Store identityKeyPair somewhere durable and safe.
            // TODO: Store registrationId somewhere durable and safe.

            var destinationPreKeyStore = new InMemoryPreKeyStore();
            foreach (var destinationPreKey in destinationPreKeys)
            {
                destinationPreKeyStore.StorePreKey(destinationPreKey.GetId(), destinationPreKey);
            }

            // Store signed prekey in SignedPreKeyStore.
            var destinationSignedPreKeyStore = new InMemorySignedPreKeyStore();
            destinationSignedPreKeyStore.StoreSignedPreKey(destinationSignedPreKey.GetId(), destinationSignedPreKey);

            var destinationSessionStore = new InMemorySessionStore();
            var destinationIdentityStore = new InMemoryIdentityKeyStore(destinationIdentityKeyPair, destinationRegistrationId);
            var destinationProtocolStore = new InMemorySignalProtocolStore(destinationIdentityKeyPair, destinationRegistrationId);
            var destinationPreKeyBundle = new PreKeyBundle(
                destinationProtocolStore.GetLocalRegistrationId(),
                destinationAddress.DeviceId,
                destinationPreKeys[0].GetId(),
                destinationPreKeys[0].GetKeyPair().GetPublicKey(),
                destinationSignedPreKey.GetId(),
                destinationSignedPreKey.GetKeyPair().GetPublicKey(),
                destinationSignedPreKey.GetSignature(),
                destinationProtocolStore.GetIdentityKeyPair().GetPublicKey()
                );

            destinationProtocolStore.StorePreKey(destinationPreKeys[0].GetId(), new PreKeyRecord(destinationPreKeyBundle.GetPreKeyId(), destinationPreKeys[0].GetKeyPair()));
            destinationProtocolStore.StoreSignedPreKey(destinationSignedPreKey.GetId(), new SignedPreKeyRecord(22, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), destinationSignedPreKey.GetKeyPair(), destinationSignedPreKey.GetSignature()));

            // Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
            var senderToDestinationSessionBuilder = new SessionBuilder(senderProtocolStore, destinationAddress);
            var destinationToSenderSessionBuilder = new SessionBuilder(destinationProtocolStore, senderAddress);
            
            // Build a session with a PreKey retrieved from the server.
            senderToDestinationSessionBuilder.Process(destinationPreKeyBundle);
            destinationToSenderSessionBuilder.Process(senderPreKeyBundle);

            SessionCipher senderToDestinationSessionCipher = new SessionCipher(senderProtocolStore, destinationAddress);


            while (true)
            {
                Console.Write("Enter the text to encrypt: ");
                var text = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(text) || text.Equals("quit", StringComparison.OrdinalIgnoreCase)) break;


                CiphertextMessage message =
                    senderToDestinationSessionCipher.Encrypt(Encoding.UTF8.GetBytes(text));


                var encryptedMessage = message.Serialize();

                Console.WriteLine("Encrypted message: {0}", Convert.ToBase64String(encryptedMessage));


                SessionCipher destinationToSenderSessionCipher =
                    new SessionCipher(destinationProtocolStore, senderAddress);


                PreKeySignalMessage incomingMessage = new PreKeySignalMessage(encryptedMessage);
                var decryptedMessage = destinationToSenderSessionCipher.Decrypt(incomingMessage);

                Console.WriteLine("Decrypted message: {0}", Encoding.UTF8.GetString(decryptedMessage));


                
            }
        }

        private static PreKeyBundle CcreatePreKeyBundle(ISignalProtocolStore store, uint preKeyId, EcKeyPair signedPreKey)
        {
            EcKeyPair aliceUnsignedPreKey = Curve.GenerateKeyPair();
            int aliceUnsignedPreKeyId = new Random().Next((int)Medium.MaxValue);
            byte[] aliceSignature = Curve.CalculateSignature(store.GetIdentityKeyPair().GetPrivateKey(),
                signedPreKey.GetPublicKey().Serialize());

            PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
                (uint)aliceUnsignedPreKeyId, aliceUnsignedPreKey.GetPublicKey(),
                preKeyId, signedPreKey.GetPublicKey(),
                aliceSignature, store.GetIdentityKeyPair().GetPublicKey());

            store.StoreSignedPreKey(preKeyId, new SignedPreKeyRecord(preKeyId, (ulong)DateTime.UtcNow.Ticks, signedPreKey, aliceSignature));
            store.StorePreKey((uint)aliceUnsignedPreKeyId, new PreKeyRecord((uint)aliceUnsignedPreKeyId, aliceUnsignedPreKey));

            return alicePreKeyBundle;
        }
    }
}
