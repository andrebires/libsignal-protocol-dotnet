using System;
using System.Collections.Generic;
using System.Diagnostics;
using Google.Protobuf;
using Libsignal.Ecc;
using Libsignal.Kdf2;
using Libsignal.Ratchet;
using Libsignal.Util;
using Strilanc.Value;

namespace Libsignal.State
{
    public class SessionState
	{
		private static readonly int MaxMessageKeys = 2000;

		private SessionStructure _sessionStructure;

		public SessionState()
		{
            _sessionStructure = new SessionStructure { };
		}

		public SessionState(SessionStructure sessionStructure)
		{
			_sessionStructure = sessionStructure;
		}

		public SessionState(SessionState copy)
		{
            _sessionStructure = new SessionStructure(copy._sessionStructure);
		}

		public SessionStructure GetStructure()
		{
			return _sessionStructure;
		}

		public byte[] GetAliceBaseKey()
		{
			return _sessionStructure.AliceBaseKey.ToByteArray();
		}

		public void SetAliceBaseKey(byte[] aliceBaseKey)
		{
            _sessionStructure.AliceBaseKey = ByteString.CopyFrom(aliceBaseKey);									 
		}

		public void SetSessionVersion(uint version)
		{
            _sessionStructure.SessionVersion = version;
		}

		public uint GetSessionVersion()
		{
			uint sessionVersion = _sessionStructure.SessionVersion;

			if (sessionVersion == 0) return 2;
			else return sessionVersion;
		}

		public void SetRemoteIdentityKey(IdentityKey identityKey)
		{
            _sessionStructure.RemoteIdentityPublic = ByteString.CopyFrom(identityKey.Serialize());
		}

		public void SetLocalIdentityKey(IdentityKey identityKey)
		{
			_sessionStructure.LocalIdentityPublic = ByteString.CopyFrom(identityKey.Serialize());
		}

		public IdentityKey GetRemoteIdentityKey()
		{
			try
			{
				if (_sessionStructure.RemoteIdentityPublicOneofCase == SessionStructure.RemoteIdentityPublicOneofOneofCase.None)
				{
					return null;
				}

				return new IdentityKey(_sessionStructure.RemoteIdentityPublic.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				Debug.WriteLine(e.ToString(), "SessionRecordV2");
				return null;
			}
		}

		public IdentityKey GetLocalIdentityKey()
		{
			try
			{
				return new IdentityKey(_sessionStructure.LocalIdentityPublic.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public uint GetPreviousCounter()
		{
			return _sessionStructure.PreviousCounter;
		}

		public void SetPreviousCounter(uint previousCounter)
		{
			_sessionStructure.PreviousCounter = previousCounter;
		}

		public RootKey GetRootKey()
		{
			return new RootKey(Hkdf.CreateFor(GetSessionVersion()),
							   _sessionStructure.RootKey.ToByteArray());
		}

		public void SetRootKey(RootKey rootKey)
		{
            _sessionStructure.RootKey = ByteString.CopyFrom(rootKey.GetKeyBytes());
		}

		public IEcPublicKey GetSenderRatchetKey()
		{
			try
			{
				return Curve.DecodePoint(_sessionStructure.SenderChain.SenderRatchetKey.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public EcKeyPair GetSenderRatchetKeyPair()
		{
			IEcPublicKey publicKey = GetSenderRatchetKey();
			IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_sessionStructure.SenderChain
																			   .SenderRatchetKeyPrivate
																			   .ToByteArray());

			return new EcKeyPair(publicKey, privateKey);
		}

		public bool HasReceiverChain(IEcPublicKey senderEphemeral)
		{
			return GetReceiverChain(senderEphemeral) != null;
		}

		public bool HasSenderChain()
		{
			return _sessionStructure.SenderChainOneofCase == SessionStructure.SenderChainOneofOneofCase.SenderChain;
		}

		private Pair<SessionStructure.Types.Chain, uint> GetReceiverChain(IEcPublicKey senderEphemeral)
		{
			IList<SessionStructure.Types.Chain> receiverChains = _sessionStructure.ReceiverChains;
			uint index = 0;

			foreach (SessionStructure.Types.Chain receiverChain in receiverChains)
			{
				try
				{
					IEcPublicKey chainSenderRatchetKey = Curve.DecodePoint(receiverChain.SenderRatchetKey.ToByteArray(), 0);

					if (chainSenderRatchetKey.Equals(senderEphemeral))
					{
						return new Pair<SessionStructure.Types.Chain, uint>(receiverChain, index);
					}
				}
				catch (InvalidKeyException e)
				{
					Debug.WriteLine(e.ToString(), "SessionRecordV2");
				}

				index++;
			}

			return null;
		}

		public ChainKey GetReceiverChainKey(IEcPublicKey senderEphemeral)
		{
			Pair<SessionStructure.Types.Chain, uint> receiverChainAndIndex = GetReceiverChain(senderEphemeral);
			SessionStructure.Types.Chain receiverChain = receiverChainAndIndex.First();

			if (receiverChain == null)
			{
				return null;
			}
			else
			{
				return new ChainKey(Hkdf.CreateFor(GetSessionVersion()),
									receiverChain.ChainKey.Key.ToByteArray(),
									receiverChain.ChainKey.Index);
			}
		}

		public void AddReceiverChain(IEcPublicKey senderRatchetKey, ChainKey chainKey)
		{
            SessionStructure.Types.Chain.Types.ChainKey chainKeyStructure = new SessionStructure.Types.Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(chainKey.GetKey()),
                Index = chainKey.GetIndex()
            };

            SessionStructure.Types.Chain chain = new SessionStructure.Types.Chain
            {
                ChainKey = chainKeyStructure,
                SenderRatchetKey = ByteString.CopyFrom(senderRatchetKey.Serialize())
            };
            _sessionStructure.ReceiverChains.Add(chain);

			while (_sessionStructure.ReceiverChains.Count > 5)
			{
                _sessionStructure.ReceiverChains.RemoveAt(0); //TODO why was here a TODO?
			}
		}

		public void SetSenderChain(EcKeyPair senderRatchetKeyPair, ChainKey chainKey)
		{
            SessionStructure.Types.Chain.Types.ChainKey chainKeyStructure = new SessionStructure.Types.Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(chainKey.GetKey()),
                Index = chainKey.GetIndex()
            };

            SessionStructure.Types.Chain senderChain = new SessionStructure.Types.Chain
            {
                SenderRatchetKey = ByteString.CopyFrom(senderRatchetKeyPair.GetPublicKey().Serialize()),
                SenderRatchetKeyPrivate = ByteString.CopyFrom(senderRatchetKeyPair.GetPrivateKey().Serialize()),
                ChainKey = chainKeyStructure
            };

            _sessionStructure.SenderChain = senderChain;
		}

		public ChainKey GetSenderChainKey()
		{
			SessionStructure.Types.Chain.Types.ChainKey chainKeyStructure = _sessionStructure.SenderChain.ChainKey;
			return new ChainKey(Hkdf.CreateFor(GetSessionVersion()),
								chainKeyStructure.Key.ToByteArray(), chainKeyStructure.Index);
		}


		public void SetSenderChainKey(ChainKey nextChainKey)
		{
            SessionStructure.Types.Chain.Types.ChainKey chainKey = new SessionStructure.Types.Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(nextChainKey.GetKey()),
                Index = nextChainKey.GetIndex()
            };

            _sessionStructure.SenderChain.ChainKey = chainKey;
		}

		public bool HasMessageKeys(IEcPublicKey senderEphemeral, uint counter)
		{
			Pair<SessionStructure.Types.Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			SessionStructure.Types.Chain chain = chainAndIndex.First();

			if (chain == null)
			{
				return false;
			}

			IList<SessionStructure.Types.Chain.Types.MessageKey> messageKeyList = chain.MessageKeys;

			foreach (SessionStructure.Types.Chain.Types.MessageKey messageKey in messageKeyList)
			{
				if (messageKey.Index == counter)
				{
					return true;
				}
			}

			return false;
		}

		public MessageKeys RemoveMessageKeys(IEcPublicKey senderEphemeral, uint counter)
		{
			Pair<SessionStructure.Types.Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			SessionStructure.Types.Chain chain = chainAndIndex.First();

			if (chain == null)
			{
				return null;
			}

			List<SessionStructure.Types.Chain.Types.MessageKey> messageKeyList = new List<SessionStructure.Types.Chain.Types.MessageKey>(chain.MessageKeys);
			IEnumerator<SessionStructure.Types.Chain.Types.MessageKey> messageKeyIterator = messageKeyList.GetEnumerator();
			MessageKeys result = null;

			while (messageKeyIterator.MoveNext()) //hasNext()
			{
				SessionStructure.Types.Chain.Types.MessageKey messageKey = messageKeyIterator.Current; // next()

				if (messageKey.Index == counter)
				{
					result = new MessageKeys(messageKey.CipherKey.ToByteArray(),
											messageKey.MacKey.ToByteArray(),
											 messageKey.Iv.ToByteArray(),
											 messageKey.Index);

					messageKeyList.Remove(messageKey); //messageKeyIterator.remove();
					break;
				}
			}

            chain.MessageKeys.Clear();
            chain.MessageKeys.AddRange(messageKeyList);

            _sessionStructure.ReceiverChains[(int)chainAndIndex.Second()] = chain;
            return result;
		}

		public void SetMessageKeys(IEcPublicKey senderEphemeral, MessageKeys messageKeys)
		{
			Pair<SessionStructure.Types.Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			SessionStructure.Types.Chain chain = chainAndIndex.First();
            SessionStructure.Types.Chain.Types.MessageKey messageKeyStructure = new SessionStructure.Types.Chain.Types.MessageKey
            {
                CipherKey = ByteString.CopyFrom(messageKeys.GetCipherKey()),
                MacKey = ByteString.CopyFrom(messageKeys.GetMacKey()),
                Index = messageKeys.GetCounter(),
                Iv = ByteString.CopyFrom(messageKeys.GetIv())
            };

            chain.MessageKeys.Add(messageKeyStructure);
			if (chain.MessageKeys.Count > MaxMessageKeys)
			{
                chain.MessageKeys.RemoveAt(0);
			}

            _sessionStructure.ReceiverChains[(int)chainAndIndex.Second()] = chain;
        }

		public void SetReceiverChainKey(IEcPublicKey senderEphemeral, ChainKey chainKey)
		{
			Pair<SessionStructure.Types.Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			SessionStructure.Types.Chain chain = chainAndIndex.First();

            SessionStructure.Types.Chain.Types.ChainKey chainKeyStructure = new SessionStructure.Types.Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(chainKey.GetKey()),
                Index = chainKey.GetIndex()
            };

            chain.ChainKey = chainKeyStructure;

            _sessionStructure.ReceiverChains[(int) chainAndIndex.Second()] = chain;
        }

		public void SetPendingKeyExchange(uint sequence,
										  EcKeyPair ourBaseKey,
										  EcKeyPair ourRatchetKey,
										  IdentityKeyPair ourIdentityKey)
		{
            SessionStructure.Types.PendingKeyExchange structure = new SessionStructure.Types.PendingKeyExchange
            {
                LocalBaseKey = ByteString.CopyFrom(ourBaseKey.GetPublicKey().Serialize()),
                LocalBaseKeyPrivate = ByteString.CopyFrom(ourBaseKey.GetPrivateKey().Serialize()),
                LocalRatchetKey = ByteString.CopyFrom(ourRatchetKey.GetPublicKey().Serialize()),
                LocalRatchetKeyPrivate = ByteString.CopyFrom(ourRatchetKey.GetPrivateKey().Serialize()),
                LocalIdentityKey = ByteString.CopyFrom(ourIdentityKey.GetPublicKey().Serialize()),
                LocalIdentityKeyPrivate = ByteString.CopyFrom(ourIdentityKey.GetPrivateKey().Serialize())
            };

            _sessionStructure.PendingKeyExchange = structure;
		}

		public uint GetPendingKeyExchangeSequence()
		{
			return _sessionStructure.PendingKeyExchange.Sequence;
		}

		public EcKeyPair GetPendingKeyExchangeBaseKey()
		{
			IEcPublicKey publicKey = Curve.DecodePoint(_sessionStructure.PendingKeyExchange
																.LocalBaseKey.ToByteArray(), 0);

			IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_sessionStructure.PendingKeyExchange
																	   .LocalBaseKeyPrivate
																	   .ToByteArray());

			return new EcKeyPair(publicKey, privateKey);
		}

		public EcKeyPair GetPendingKeyExchangeRatchetKey()
		{
			IEcPublicKey publicKey = Curve.DecodePoint(_sessionStructure.PendingKeyExchange
																.LocalRatchetKey.ToByteArray(), 0);

			IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_sessionStructure.PendingKeyExchange
																	   .LocalRatchetKeyPrivate
																	   .ToByteArray());

			return new EcKeyPair(publicKey, privateKey);
		}

		public IdentityKeyPair GetPendingKeyExchangeIdentityKey()
		{
			IdentityKey publicKey = new IdentityKey(_sessionStructure.PendingKeyExchange
															.LocalIdentityKey.ToByteArray(), 0);

			IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_sessionStructure.PendingKeyExchange
																	   .LocalIdentityKeyPrivate
																	   .ToByteArray());

			return new IdentityKeyPair(publicKey, privateKey);
		}

		public bool HasPendingKeyExchange()
		{
			return _sessionStructure.PendingKeyExchangeOneofCase == SessionStructure.PendingKeyExchangeOneofOneofCase.PendingKeyExchange;
		}

		public void SetUnacknowledgedPreKeyMessage(May<uint> preKeyId, uint signedPreKeyId, IEcPublicKey baseKey)
		{
            SessionStructure.Types.PendingPreKey pending = new SessionStructure.Types.PendingPreKey
            {
                SignedPreKeyId = (int) signedPreKeyId,
                BaseKey = ByteString.CopyFrom(baseKey.Serialize())
            };

			if (preKeyId.HasValue)
			{
                pending.PreKeyId = preKeyId.ForceGetValue();
			}

            _sessionStructure.PendingPreKey = pending;
		}

		public bool HasUnacknowledgedPreKeyMessage()
		{
			return _sessionStructure.PendingPreKeyOneofCase == SessionStructure.PendingPreKeyOneofOneofCase.PendingPreKey;
		}

		public UnacknowledgedPreKeyMessageItems GetUnacknowledgedPreKeyMessageItems()
		{
			try
			{
				May<uint> preKeyId;

				if (_sessionStructure.PendingPreKey.PreKeyIdOneofCase != SessionStructure.Types.PendingPreKey.PreKeyIdOneofOneofCase.None)
				{
					preKeyId = new May<uint>(_sessionStructure.PendingPreKey.PreKeyId);
				}
				else
				{
					preKeyId = May<uint>.NoValue;
				}

				return
					new UnacknowledgedPreKeyMessageItems(preKeyId,
														 (uint)_sessionStructure.PendingPreKey.SignedPreKeyId,
														 Curve.DecodePoint(_sessionStructure.PendingPreKey
																						   .BaseKey
																						   .ToByteArray(), 0));
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public void ClearUnacknowledgedPreKeyMessage()
		{
            _sessionStructure.PendingPreKey = null;
		}

		public void SetRemoteRegistrationId(uint registrationId)
		{
            _sessionStructure.RemoteRegistrationId = registrationId;
		}

		public uint GetRemoteRegistrationId()
		{
			return _sessionStructure.RemoteRegistrationId;
		}

		public void SetLocalRegistrationId(uint registrationId)
		{
            _sessionStructure.LocalRegistrationId = registrationId;
		}

		public uint GetLocalRegistrationId()
		{
			return _sessionStructure.LocalRegistrationId;
		}

		public byte[] Serialize()
		{
			return _sessionStructure.ToByteArray();
		}

		public class UnacknowledgedPreKeyMessageItems
		{
			private readonly May<uint> _preKeyId;
			private readonly uint _signedPreKeyId;
			private readonly IEcPublicKey _baseKey;

			public UnacknowledgedPreKeyMessageItems(May<uint> preKeyId,
													uint signedPreKeyId,
													IEcPublicKey baseKey)
			{
				_preKeyId = preKeyId;
				_signedPreKeyId = signedPreKeyId;
				_baseKey = baseKey;
			}


			public May<uint> GetPreKeyId()
			{
				return _preKeyId;
			}

			public uint GetSignedPreKeyId()
			{
				return _signedPreKeyId;
			}

			public IEcPublicKey GetBaseKey()
			{
				return _baseKey;
			}
		}
	}
}
