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

namespace libsignal.groups
{
    /**
     * A representation of a (groupId + senderId + deviceId) tuple.
     */
    public class SenderKeyName
    {

        private readonly String _groupId;
        private readonly SignalProtocolAddress _sender;

        public SenderKeyName(String groupId, SignalProtocolAddress sender)
        {
            this._groupId = groupId;
            this._sender = sender;
        }

        public String GetGroupId()
        {
            return _groupId;
        }

        public SignalProtocolAddress GetSender()
        {
            return _sender;
        }

        public String Serialize()
        {
            return _groupId + "::" + _sender.Name + "::" + _sender.DeviceId;
        }


        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is SenderKeyName)) return false;

            SenderKeyName that = (SenderKeyName)other;

            return
                this._groupId.Equals(that._groupId) &&
                this._sender.Equals(that._sender);
        }

        public override int GetHashCode()
        {
            return this._groupId.GetHashCode() ^ this._sender.GetHashCode();
        }

    }
}
