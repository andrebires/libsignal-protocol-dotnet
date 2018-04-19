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
using System.Collections.Generic;

namespace Libsignal.State.Impl
{
    public class InMemoryPreKeyStore : IPreKeyStore
	{

		private readonly IDictionary<uint, byte[]> _store = new Dictionary<uint, byte[]>();


		public PreKeyRecord LoadPreKey(uint preKeyId)
		{
			try
			{
				if (!_store.ContainsKey(preKeyId))
				{
					throw new InvalidKeyIdException("No such prekeyrecord!");
				}
				byte[] record;
				_store.TryGetValue(preKeyId, out record);  // get()

				return new PreKeyRecord(record);
			}
			catch (Exception e)
			{
				throw new Exception(e.Message);
			}
		}


		public void StorePreKey(uint preKeyId, PreKeyRecord record)
		{
			_store[preKeyId] = record.Serialize();
		}


		public bool ContainsPreKey(uint preKeyId)
		{
			return _store.ContainsKey(preKeyId);
		}


		public void RemovePreKey(uint preKeyId)
		{
			_store.Remove(preKeyId);
		}
	}
}
