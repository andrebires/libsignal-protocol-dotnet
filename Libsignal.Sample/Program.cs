using System;
using System.Text;
using libsignal;
using libsignal.ecc;
using libsignal.protocol;
using libsignal.state;
using libsignal.state.impl;
using libsignal.util;

namespace Libsignal.Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            // 1. Sender setup

            // At install time, a libsignal client needs to generate its identity keys, registration id, and prekeys.
            var senderIdentityKeyPair = KeyHelper.generateIdentityKeyPair();
            var senderRegistrationId = KeyHelper.generateRegistrationId(false);
            var senderPreKeys = KeyHelper.generatePreKeys(0, 100);
            var senderSignedPreKey = KeyHelper.generateSignedPreKey(senderIdentityKeyPair, KeyHelper.generateSenderKeyId());
            var senderAddress = new SignalProtocolAddress("sender", 1);

            // TODO: Store identityKeyPair somewhere durable and safe.
            // TODO: Store registrationId somewhere durable and safe.

            // Store preKeys in PreKeyStore.            
            var senderPreKeyStore = new InMemoryPreKeyStore();
            foreach (var senderPreKey in senderPreKeys)
            {
                senderPreKeyStore.StorePreKey(senderPreKey.getId(), senderPreKey);
            }

            // Store signed prekey in SignedPreKeyStore.
            var senderSignedPreKeyStore = new InMemorySignedPreKeyStore();
            senderSignedPreKeyStore.StoreSignedPreKey(senderSignedPreKey.getId(), senderSignedPreKey);

            var senderSessionStore = new InMemorySessionStore();
            var senderIdentityStore = new InMemoryIdentityKeyStore(senderIdentityKeyPair, senderRegistrationId);
            var senderProtocolStore = new InMemorySignalProtocolStore(senderIdentityKeyPair, senderRegistrationId);
            var senderPreKeyBundle = new PreKeyBundle(
                senderProtocolStore.GetLocalRegistrationId(),
                senderAddress.DeviceId,
                senderPreKeys[0].getId(),
                senderPreKeys[0].getKeyPair().getPublicKey(),
                senderSignedPreKey.getId(),
                senderSignedPreKey.getKeyPair().getPublicKey(),
                senderSignedPreKey.getSignature(),
                senderProtocolStore.GetIdentityKeyPair().getPublicKey()
            );

            senderProtocolStore.StorePreKey(senderPreKeys[0].getId(), new PreKeyRecord(senderPreKeyBundle.getPreKeyId(), senderPreKeys[0].getKeyPair()));
            senderProtocolStore.StoreSignedPreKey(senderSignedPreKey.getId(), new SignedPreKeyRecord(22, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), senderSignedPreKey.getKeyPair(), senderSignedPreKey.getSignature()));


            // 2. Destination setup
            var destinationIdentityKeyPair = KeyHelper.generateIdentityKeyPair();
            var destinationRegistrationId = KeyHelper.generateRegistrationId(false);
            var destinationPreKeys = KeyHelper.generatePreKeys(0, 100);
            var destinationSignedPreKey = KeyHelper.generateSignedPreKey(destinationIdentityKeyPair, KeyHelper.generateSenderKeyId());
            var destinationAddress = new SignalProtocolAddress("destination", 1);

            // TODO: Store identityKeyPair somewhere durable and safe.
            // TODO: Store registrationId somewhere durable and safe.

            var destinationPreKeyStore = new InMemoryPreKeyStore();
            foreach (var destinationPreKey in destinationPreKeys)
            {
                destinationPreKeyStore.StorePreKey(destinationPreKey.getId(), destinationPreKey);
            }

            // Store signed prekey in SignedPreKeyStore.
            var destinationSignedPreKeyStore = new InMemorySignedPreKeyStore();
            destinationSignedPreKeyStore.StoreSignedPreKey(destinationSignedPreKey.getId(), destinationSignedPreKey);

            var destinationSessionStore = new InMemorySessionStore();
            var destinationIdentityStore = new InMemoryIdentityKeyStore(destinationIdentityKeyPair, destinationRegistrationId);
            var destinationProtocolStore = new InMemorySignalProtocolStore(destinationIdentityKeyPair, destinationRegistrationId);
            var destinationPreKeyBundle = new PreKeyBundle(
                destinationProtocolStore.GetLocalRegistrationId(),
                destinationAddress.DeviceId,
                destinationPreKeys[0].getId(),
                destinationPreKeys[0].getKeyPair().getPublicKey(),
                destinationSignedPreKey.getId(),
                destinationSignedPreKey.getKeyPair().getPublicKey(),
                destinationSignedPreKey.getSignature(),
                destinationProtocolStore.GetIdentityKeyPair().getPublicKey()
                );

            destinationProtocolStore.StorePreKey(destinationPreKeys[0].getId(), new PreKeyRecord(destinationPreKeyBundle.getPreKeyId(), destinationPreKeys[0].getKeyPair()));
            destinationProtocolStore.StoreSignedPreKey(destinationSignedPreKey.getId(), new SignedPreKeyRecord(22, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), destinationSignedPreKey.getKeyPair(), destinationSignedPreKey.getSignature()));

            // Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
            var senderToDestinationSessionBuilder = new SessionBuilder(senderProtocolStore, destinationAddress);
            var destinationToSenderSessionBuilder = new SessionBuilder(destinationProtocolStore, senderAddress);
            
            // Build a session with a PreKey retrieved from the server.
            senderToDestinationSessionBuilder.process(destinationPreKeyBundle);
            destinationToSenderSessionBuilder.process(senderPreKeyBundle);

            SessionCipher senderToDestinationSessionCipher = new SessionCipher(senderProtocolStore, destinationAddress);


            while (true)
            {
                Console.Write("Enter the text to encrypt: ");
                var text = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(text) || text.Equals("quit", StringComparison.OrdinalIgnoreCase)) break;


                CiphertextMessage message =
                    senderToDestinationSessionCipher.encrypt(Encoding.UTF8.GetBytes(text));


                var encryptedMessage = message.serialize();

                Console.WriteLine("Encrypted message: {0}", Convert.ToBase64String(encryptedMessage));


                SessionCipher destinationToSenderSessionCipher =
                    new SessionCipher(destinationProtocolStore, senderAddress);


                PreKeySignalMessage incomingMessage = new PreKeySignalMessage(encryptedMessage);
                var decryptedMessage = destinationToSenderSessionCipher.decrypt(incomingMessage);

                Console.WriteLine("Decrypted message: {0}", Encoding.UTF8.GetString(decryptedMessage));


                
            }
        }

        private static PreKeyBundle CcreatePreKeyBundle(SignalProtocolStore store, uint preKeyId, ECKeyPair signedPreKey)
        {
            ECKeyPair aliceUnsignedPreKey = Curve.generateKeyPair();
            int aliceUnsignedPreKeyId = new Random().Next((int)Medium.MAX_VALUE);
            byte[] aliceSignature = Curve.calculateSignature(store.GetIdentityKeyPair().getPrivateKey(),
                signedPreKey.getPublicKey().serialize());

            PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
                (uint)aliceUnsignedPreKeyId, aliceUnsignedPreKey.getPublicKey(),
                preKeyId, signedPreKey.getPublicKey(),
                aliceSignature, store.GetIdentityKeyPair().getPublicKey());

            store.StoreSignedPreKey(preKeyId, new SignedPreKeyRecord(preKeyId, (ulong)DateTime.UtcNow.Ticks, signedPreKey, aliceSignature));
            store.StorePreKey((uint)aliceUnsignedPreKeyId, new PreKeyRecord((uint)aliceUnsignedPreKeyId, aliceUnsignedPreKey));

            return alicePreKeyBundle;
        }
    }
}
