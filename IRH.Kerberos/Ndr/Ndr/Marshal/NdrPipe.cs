using System;

namespace IRH.Kerberos.Ndr.Marshal
{
    public class NdrPipe<T> where T : struct
    {
        public T[] Pull(int count)
        {
            throw new NotImplementedException("Pipe support not implemented");
        }

        public void Push(T[] data)
        {
            throw new NotImplementedException("Pipe support not implemented");
        }
    }
}
