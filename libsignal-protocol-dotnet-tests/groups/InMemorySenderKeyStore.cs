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

using System;
using System.Collections.Generic;
using System.IO;
using Libsignal.Groups;
using Libsignal.Groups.State;

namespace libsignal_test.groups
{
    class InMemorySenderKeyStore : ISenderKeyStore
    {
        private readonly Dictionary<SenderKeyName, SenderKeyRecord> _store = new Dictionary<SenderKeyName, SenderKeyRecord>();

        public void StoreSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record)
        {
            _store[senderKeyName] = record;
        }

        public SenderKeyRecord LoadSenderKey(SenderKeyName senderKeyName)
        {
            try
            {
                SenderKeyRecord record;
                _store.TryGetValue(senderKeyName, out record);

                if (record == null)
                {
                    return new SenderKeyRecord();
                }
                else
                {
                    return new SenderKeyRecord(record.Serialize());
                }
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }
    }
}
