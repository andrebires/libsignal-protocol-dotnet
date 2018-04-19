using libsignal.ecc;
using libsignal.kdf;
using libsignal.ratchet;
using libsignal.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using Google.Protobuf;
using static libsignal.state.SessionStructure;
using static libsignal.state.SessionStructure.Types;

namespace libsignal.state
{
    public class SessionState
	{
		private static readonly int MaxMessageKeys = 2000;

		private SessionStructure _sessionStructure;

		public SessionState()
		{
            this._sessionStructure = new SessionStructure { };
		}

		public SessionState(SessionStructure sessionStructure)
		{
			this._sessionStructure = sessionStructure;
		}

		public SessionState(SessionState copy)
		{
            this._sessionStructure = new SessionStructure(copy._sessionStructure);
		}

		public SessionStructure GetStructure()
		{
			return _sessionStructure;
		}

		public byte[] GetAliceBaseKey()
		{
			return this._sessionStructure.AliceBaseKey.ToByteArray();
		}

		public void SetAliceBaseKey(byte[] aliceBaseKey)
		{
            this._sessionStructure.AliceBaseKey = ByteString.CopyFrom(aliceBaseKey);									 
		}

		public void SetSessionVersion(uint version)
		{
            this._sessionStructure.SessionVersion = version;
		}

		public uint GetSessionVersion()
		{
			uint sessionVersion = this._sessionStructure.SessionVersion;

			if (sessionVersion == 0) return 2;
			else return sessionVersion;
		}

		public void SetRemoteIdentityKey(IdentityKey identityKey)
		{
            this._sessionStructure.RemoteIdentityPublic = ByteString.CopyFrom(identityKey.Serialize());
		}

		public void SetLocalIdentityKey(IdentityKey identityKey)
		{
			this._sessionStructure.LocalIdentityPublic = ByteString.CopyFrom(identityKey.Serialize());
		}

		public IdentityKey GetRemoteIdentityKey()
		{
			try
			{
				if (this._sessionStructure.RemoteIdentityPublicOneofCase == RemoteIdentityPublicOneofOneofCase.None)
				{
					return null;
				}

				return new IdentityKey(this._sessionStructure.RemoteIdentityPublic.ToByteArray(), 0);
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
				return new IdentityKey(this._sessionStructure.LocalIdentityPublic.ToByteArray(), 0);
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
			this._sessionStructure.PreviousCounter = previousCounter;
		}

		public RootKey GetRootKey()
		{
			return new RootKey(Hkdf.CreateFor(GetSessionVersion()),
							   this._sessionStructure.RootKey.ToByteArray());
		}

		public void SetRootKey(RootKey rootKey)
		{
            this._sessionStructure.RootKey = ByteString.CopyFrom(rootKey.GetKeyBytes());
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
			return _sessionStructure.SenderChainOneofCase == SenderChainOneofOneofCase.SenderChain;
		}

		private Pair<Chain, uint> GetReceiverChain(IEcPublicKey senderEphemeral)
		{
			IList<Chain> receiverChains = _sessionStructure.ReceiverChains;
			uint index = 0;

			foreach (Chain receiverChain in receiverChains)
			{
				try
				{
					IEcPublicKey chainSenderRatchetKey = Curve.DecodePoint(receiverChain.SenderRatchetKey.ToByteArray(), 0);

					if (chainSenderRatchetKey.Equals(senderEphemeral))
					{
						return new Pair<Chain, uint>(receiverChain, index);
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
			Pair<Chain, uint> receiverChainAndIndex = GetReceiverChain(senderEphemeral);
			Chain receiverChain = receiverChainAndIndex.First();

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
            Chain.Types.ChainKey chainKeyStructure = new Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(chainKey.GetKey()),
                Index = chainKey.GetIndex()
            };

            Chain chain = new Chain
            {
                ChainKey = chainKeyStructure,
                SenderRatchetKey = ByteString.CopyFrom(senderRatchetKey.Serialize())
            };
            this._sessionStructure.ReceiverChains.Add(chain);

			while (this._sessionStructure.ReceiverChains.Count > 5)
			{
                this._sessionStructure.ReceiverChains.RemoveAt(0); //TODO why was here a TODO?
			}
		}

		public void SetSenderChain(EcKeyPair senderRatchetKeyPair, ChainKey chainKey)
		{
            Chain.Types.ChainKey chainKeyStructure = new Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(chainKey.GetKey()),
                Index = chainKey.GetIndex()
            };

            Chain senderChain = new Chain
            {
                SenderRatchetKey = ByteString.CopyFrom(senderRatchetKeyPair.GetPublicKey().Serialize()),
                SenderRatchetKeyPrivate = ByteString.CopyFrom(senderRatchetKeyPair.GetPrivateKey().Serialize()),
                ChainKey = chainKeyStructure
            };

            this._sessionStructure.SenderChain = senderChain;
		}

		public ChainKey GetSenderChainKey()
		{
			Chain.Types.ChainKey chainKeyStructure = _sessionStructure.SenderChain.ChainKey;
			return new ChainKey(Hkdf.CreateFor(GetSessionVersion()),
								chainKeyStructure.Key.ToByteArray(), chainKeyStructure.Index);
		}


		public void SetSenderChainKey(ChainKey nextChainKey)
		{
            Chain.Types.ChainKey chainKey = new Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(nextChainKey.GetKey()),
                Index = nextChainKey.GetIndex()
            };

            _sessionStructure.SenderChain.ChainKey = chainKey;
		}

		public bool HasMessageKeys(IEcPublicKey senderEphemeral, uint counter)
		{
			Pair<Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.First();

			if (chain == null)
			{
				return false;
			}

			IList<Chain.Types.MessageKey> messageKeyList = chain.MessageKeys;

			foreach (Chain.Types.MessageKey messageKey in messageKeyList)
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
			Pair<Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.First();

			if (chain == null)
			{
				return null;
			}

			List<Chain.Types.MessageKey> messageKeyList = new List<Chain.Types.MessageKey>(chain.MessageKeys);
			IEnumerator<Chain.Types.MessageKey> messageKeyIterator = messageKeyList.GetEnumerator();
			MessageKeys result = null;

			while (messageKeyIterator.MoveNext()) //hasNext()
			{
				Chain.Types.MessageKey messageKey = messageKeyIterator.Current; // next()

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
			Pair<Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.First();
            Chain.Types.MessageKey messageKeyStructure = new Chain.Types.MessageKey
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
			Pair<Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.First();

            Chain.Types.ChainKey chainKeyStructure = new Chain.Types.ChainKey
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
            PendingKeyExchange structure = new PendingKeyExchange
            {
                LocalBaseKey = ByteString.CopyFrom(ourBaseKey.GetPublicKey().Serialize()),
                LocalBaseKeyPrivate = ByteString.CopyFrom(ourBaseKey.GetPrivateKey().Serialize()),
                LocalRatchetKey = ByteString.CopyFrom(ourRatchetKey.GetPublicKey().Serialize()),
                LocalRatchetKeyPrivate = ByteString.CopyFrom(ourRatchetKey.GetPrivateKey().Serialize()),
                LocalIdentityKey = ByteString.CopyFrom(ourIdentityKey.GetPublicKey().Serialize()),
                LocalIdentityKeyPrivate = ByteString.CopyFrom(ourIdentityKey.GetPrivateKey().Serialize())
            };

            this._sessionStructure.PendingKeyExchange = structure;
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
			return _sessionStructure.PendingKeyExchangeOneofCase == PendingKeyExchangeOneofOneofCase.PendingKeyExchange;
		}

		public void SetUnacknowledgedPreKeyMessage(May<uint> preKeyId, uint signedPreKeyId, IEcPublicKey baseKey)
		{
            PendingPreKey pending = new PendingPreKey
            {
                SignedPreKeyId = (int) signedPreKeyId,
                BaseKey = ByteString.CopyFrom(baseKey.Serialize())
            };

			if (preKeyId.HasValue)
			{
                pending.PreKeyId = preKeyId.ForceGetValue();
			}

            this._sessionStructure.PendingPreKey = pending;
		}

		public bool HasUnacknowledgedPreKeyMessage()
		{
			return this._sessionStructure.PendingPreKeyOneofCase == PendingPreKeyOneofOneofCase.PendingPreKey;
		}

		public UnacknowledgedPreKeyMessageItems GetUnacknowledgedPreKeyMessageItems()
		{
			try
			{
				May<uint> preKeyId;

				if (_sessionStructure.PendingPreKey.PreKeyIdOneofCase != PendingPreKey.PreKeyIdOneofOneofCase.None)
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
            this._sessionStructure.PendingPreKey = null;
		}

		public void SetRemoteRegistrationId(uint registrationId)
		{
            this._sessionStructure.RemoteRegistrationId = registrationId;
		}

		public uint GetRemoteRegistrationId()
		{
			return this._sessionStructure.RemoteRegistrationId;
		}

		public void SetLocalRegistrationId(uint registrationId)
		{
            this._sessionStructure.LocalRegistrationId = registrationId;
		}

		public uint GetLocalRegistrationId()
		{
			return this._sessionStructure.LocalRegistrationId;
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
				this._preKeyId = preKeyId;
				this._signedPreKeyId = signedPreKeyId;
				this._baseKey = baseKey;
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
