using System.Collections.Generic;
using Google.Protobuf;
using Libsignal.Ecc;
using Libsignal.Groups.Ratchet;
using Libsignal.State;
using Strilanc.Value;
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

namespace Libsignal.Groups.State
{
    /**
     * Represents the state of an individual SenderKey ratchet.
     *
     * @author
     */
    public class SenderKeyState
	{
		private static readonly int MaxMessageKeys = 2000;

		private SenderKeyStateStructure _senderKeyStateStructure;

		public SenderKeyState(uint id, uint iteration, byte[] chainKey, IEcPublicKey signatureKey)
			: this(id, iteration, chainKey, signatureKey, May<IEcPrivateKey>.NoValue)
		{
		}

		public SenderKeyState(uint id, uint iteration, byte[] chainKey, EcKeyPair signatureKey)
		: this(id, iteration, chainKey, signatureKey.GetPublicKey(), new May<IEcPrivateKey>(signatureKey.GetPrivateKey()))
		{
		}

		private SenderKeyState(uint id, uint iteration, byte[] chainKey,
							  IEcPublicKey signatureKeyPublic,
							  May<IEcPrivateKey> signatureKeyPrivate)
		{
            SenderKeyStateStructure.Types.SenderChainKey senderChainKeyStructure = new SenderKeyStateStructure.Types.SenderChainKey
            {
                Iteration = iteration,
                Seed = ByteString.CopyFrom(chainKey)
            };

            SenderKeyStateStructure.Types.SenderSigningKey signingKeyStructure = new SenderKeyStateStructure.Types.SenderSigningKey
            {
                Public = ByteString.CopyFrom(signatureKeyPublic.Serialize())
            };

			if (signatureKeyPrivate.HasValue)
			{
				signingKeyStructure.Private = ByteString.CopyFrom(signatureKeyPrivate.ForceGetValue().Serialize());
			}

            _senderKeyStateStructure = new SenderKeyStateStructure
            {
                SenderKeyId = id,
                SenderChainKey = senderChainKeyStructure,
                SenderSigningKey = signingKeyStructure
            };
		}

		public SenderKeyState(SenderKeyStateStructure senderKeyStateStructure)
		{
			_senderKeyStateStructure = senderKeyStateStructure;
		}

		public uint GetKeyId()
		{
			return _senderKeyStateStructure.SenderKeyId;
		}

		public SenderChainKey GetSenderChainKey()
		{
			return new SenderChainKey(_senderKeyStateStructure.SenderChainKey.Iteration,
									  _senderKeyStateStructure.SenderChainKey.Seed.ToByteArray());
		}

		public void SetSenderChainKey(SenderChainKey chainKey)
		{
            SenderKeyStateStructure.Types.SenderChainKey senderChainKeyStructure = new SenderKeyStateStructure.Types.SenderChainKey
            {
                Iteration = chainKey.GetIteration(),
                Seed = ByteString.CopyFrom(chainKey.GetSeed())
            };

            _senderKeyStateStructure.SenderChainKey = senderChainKeyStructure;
		}

		public IEcPublicKey GetSigningKeyPublic()
		{
			return Curve.DecodePoint(_senderKeyStateStructure.SenderSigningKey.Public.ToByteArray(), 0);
		}

		public IEcPrivateKey GetSigningKeyPrivate()
		{
			return Curve.DecodePrivatePoint(_senderKeyStateStructure.SenderSigningKey.Private.ToByteArray());
		}

		public bool HasSenderMessageKey(uint iteration)
		{
			foreach (SenderKeyStateStructure.Types.SenderMessageKey senderMessageKey in _senderKeyStateStructure.SenderMessageKeys)
			{
				if (senderMessageKey.Iteration == iteration) return true;
			}

			return false;
		}

		public void AddSenderMessageKey(SenderMessageKey senderMessageKey)
		{
            SenderKeyStateStructure.Types.SenderMessageKey senderMessageKeyStructure = new SenderKeyStateStructure.Types.SenderMessageKey
            {
                Iteration = senderMessageKey.GetIteration(),
                Seed = ByteString.CopyFrom(senderMessageKey.GetSeed())
            };
            _senderKeyStateStructure.SenderMessageKeys.Add(senderMessageKeyStructure);

			if (_senderKeyStateStructure.SenderMessageKeys.Count > MaxMessageKeys)
			{
                _senderKeyStateStructure.SenderMessageKeys.RemoveAt(0);
			}
		}

		public SenderMessageKey RemoveSenderMessageKey(uint iteration)
		{
			LinkedList<SenderKeyStateStructure.Types.SenderMessageKey> keys = new LinkedList<SenderKeyStateStructure.Types.SenderMessageKey>(_senderKeyStateStructure.SenderMessageKeys);
			IEnumerator<SenderKeyStateStructure.Types.SenderMessageKey> iterator = keys.GetEnumerator(); // iterator();

			SenderKeyStateStructure.Types.SenderMessageKey result = null;

			while (iterator.MoveNext()) // hastNext
			{
				SenderKeyStateStructure.Types.SenderMessageKey senderMessageKey = iterator.Current; // next();

				if (senderMessageKey.Iteration == iteration) //senderMessageKey.getIteration()
				{
					result = senderMessageKey;
					keys.Remove(senderMessageKey); //iterator.remove();
					break;
				}
			}

            _senderKeyStateStructure.SenderMessageKeys.Clear();
            _senderKeyStateStructure.SenderMessageKeys.AddRange(keys);

			if (result != null)
			{
				return new SenderMessageKey(result.Iteration, result.Seed.ToByteArray());
			}
			else
			{
				return null;
			}
		}

		public SenderKeyStateStructure GetStructure()
		{
			return _senderKeyStateStructure;
		}
	}
}
