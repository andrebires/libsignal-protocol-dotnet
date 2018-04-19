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

namespace Libsignal.Util
{
    public class Pair<T1, T2>
    {
        private readonly T1 _v1;
        private readonly T2 _v2;

        public Pair(T1 v1, T2 v2)
        {
            _v1 = v1;
            _v2 = v2;
        }

        public T1 First()
        {
            return _v1;
        }

        public T2 Second()
        {
            return _v2;
        }

        public override bool Equals(object o)
        {
            return o is Pair<T1, T2> &&
                Equal(((Pair<T1, T2>)o).First(), First()) &&
                Equal(((Pair<T1, T2>)o).Second(), Second());
        }

        public override int GetHashCode()
        {
            return First().GetHashCode() ^ Second().GetHashCode();
        }

        private bool Equal(Object first, Object second)
        {
            if (first == null && second == null) return true;
            if (first == null || second == null) return false;
            return first.Equals(second);
        }
    }
}
